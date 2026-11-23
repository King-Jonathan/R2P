#include "crypto/bip340.hpp"

#include <cstring>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <string>
#include <vector>

#include "crypto/cipher.hpp"

namespace r2p {

namespace {

std::array<uint8_t, 32> tagged_hash(const char* tag, const uint8_t* data, size_t len) {
    std::array<uint8_t, 32> th = sha256(reinterpret_cast<const uint8_t*>(tag), std::strlen(tag));
    std::vector<uint8_t> buf(64 + len);
    std::memcpy(buf.data(), th.data(), 32);
    std::memcpy(buf.data() + 32, th.data(), 32);
    if (len > 0) std::memcpy(buf.data() + 64, data, len);
    return sha256(buf.data(), buf.size());
}

struct Secp256k1Ctx {
    EC_GROUP* group;
    BN_CTX* bn_ctx;
    const BIGNUM* n;
    BIGNUM* p;
    BIGNUM* exp_sqrt;  // (p + 1) / 4

    Secp256k1Ctx()
        : group(EC_GROUP_new_by_curve_name(NID_secp256k1)),
          bn_ctx(BN_CTX_new()),
          n(nullptr),
          p(BN_new()),
          exp_sqrt(BN_new()) {
        if (group && bn_ctx && p && exp_sqrt) {
            n = EC_GROUP_get0_order(group);
            BIGNUM* a = BN_new();
            BIGNUM* b = BN_new();
            EC_GROUP_get_curve(group, p, a, b, bn_ctx);
            BN_copy(exp_sqrt, p);
            BN_add_word(exp_sqrt, 1);
            BN_rshift(exp_sqrt, exp_sqrt, 2);
            BN_free(a);
            BN_free(b);
        }
    }

    ~Secp256k1Ctx() {
        BN_free(exp_sqrt);
        BN_free(p);
        BN_CTX_free(bn_ctx);
        EC_GROUP_free(group);
    }

    bool ok() const { return group && bn_ctx && n && p && exp_sqrt; }
};

bool lift_x(const Secp256k1Ctx& c, const BIGNUM* x, EC_POINT* out) {
    if (BN_is_negative(x) || BN_cmp(x, c.p) >= 0) return false;
    BIGNUM* y2 = BN_new();
    BIGNUM* y = BN_new();
    BIGNUM* check = BN_new();
    bool ok = false;
    if (y2 && y && check) {
        // y2 = (x^3 + 7) mod p
        BN_mod_sqr(y2, x, c.p, c.bn_ctx);
        BN_mod_mul(y2, y2, x, c.p, c.bn_ctx);
        BN_add_word(y2, 7);
        BN_nnmod(y2, y2, c.p, c.bn_ctx);
        BN_mod_exp(y, y2, c.exp_sqrt, c.p, c.bn_ctx);
        BN_mod_sqr(check, y, c.p, c.bn_ctx);
        if (BN_cmp(check, y2) == 0) {
            if (BN_is_odd(y)) {
                BN_sub(y, c.p, y);
            }
            ok = (EC_POINT_set_affine_coordinates(c.group, out, x, y, c.bn_ctx) == 1);
        }
    }
    BN_free(check);
    BN_free(y);
    BN_free(y2);
    return ok;
}

}  // namespace

bool bip340_generate_keypair(std::array<uint8_t, 32>& priv_out,
                             std::array<uint8_t, 32>& pub_xonly_out) {
    Secp256k1Ctx c;
    if (!c.ok()) return false;
    BIGNUM* d = BN_new();
    BIGNUM* px = BN_new();
    BIGNUM* py = BN_new();
    EC_POINT* pt = EC_POINT_new(c.group);
    bool ok = false;
    if (d && px && py && pt) {
        BN_set_flags(d, BN_FLG_CONSTTIME);
        for (int tries = 0; tries < 64; ++tries) {
            if (RAND_bytes(priv_out.data(), 32) != 1) break;
            BN_bin2bn(priv_out.data(), 32, d);
            if (BN_is_zero(d) || BN_cmp(d, c.n) >= 0) continue;
            if (EC_POINT_mul(c.group, pt, d, nullptr, nullptr, c.bn_ctx) != 1) continue;
            if (EC_POINT_is_at_infinity(c.group, pt)) continue;
            if (EC_POINT_get_affine_coordinates(c.group, pt, px, py, c.bn_ctx) != 1) continue;
            if (BN_is_odd(py)) {
                BN_sub(d, c.n, d);
            }
            BN_bn2binpad(d, priv_out.data(), 32);
            BN_bn2binpad(px, pub_xonly_out.data(), 32);
            ok = true;
            break;
        }
    }
    EC_POINT_free(pt);
    BN_clear_free(py);
    BN_clear_free(px);
    BN_clear_free(d);
    return ok;
}

bool bip340_sign(const std::array<uint8_t, 32>& msg32,
                 const std::array<uint8_t, 32>& priv32,
                 std::array<uint8_t, 64>& sig_out) {
    Secp256k1Ctx c;
    if (!c.ok()) return false;
    BIGNUM* d = BN_bin2bn(priv32.data(), 32, nullptr);
    BIGNUM* px = BN_new();
    BIGNUM* py = BN_new();
    BIGNUM* k = BN_new();
    BIGNUM* rx = BN_new();
    BIGNUM* ry = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* s = BN_new();
    EC_POINT* P = EC_POINT_new(c.group);
    EC_POINT* R = EC_POINT_new(c.group);
    bool ok = false;

    if (d && px && py && k && rx && ry && e && s && P && R) {
        BN_set_flags(d, BN_FLG_CONSTTIME);
        BN_set_flags(k, BN_FLG_CONSTTIME);
        if (!BN_is_zero(d) && BN_cmp(d, c.n) < 0 &&
            EC_POINT_mul(c.group, P, d, nullptr, nullptr, c.bn_ctx) == 1 &&
            !EC_POINT_is_at_infinity(c.group, P) &&
            EC_POINT_get_affine_coordinates(c.group, P, px, py, c.bn_ctx) == 1) {
            if (BN_is_odd(py)) BN_sub(d, c.n, d);
            uint8_t d_bytes[32];
            uint8_t pub_bytes[32];
            BN_bn2binpad(d, d_bytes, 32);
            BN_bn2binpad(px, pub_bytes, 32);

            uint8_t aux[32];
            if (RAND_bytes(aux, 32) == 1) {
                std::array<uint8_t, 32> aux_h = tagged_hash("BIP0340/aux", aux, 32);
                uint8_t nonce_in[96];
                for (int i = 0; i < 32; ++i) nonce_in[i] = d_bytes[i] ^ aux_h[i];
                std::memcpy(nonce_in + 32, pub_bytes, 32);
                std::memcpy(nonce_in + 64, msg32.data(), 32);
                std::array<uint8_t, 32> rand_h = tagged_hash("BIP0340/nonce", nonce_in, 96);
                OPENSSL_cleanse(nonce_in, sizeof(nonce_in));
                BN_bin2bn(rand_h.data(), 32, k);
                BN_nnmod(k, k, c.n, c.bn_ctx);
                if (!BN_is_zero(k) &&
                    EC_POINT_mul(c.group, R, k, nullptr, nullptr, c.bn_ctx) == 1 &&
                    !EC_POINT_is_at_infinity(c.group, R) &&
                    EC_POINT_get_affine_coordinates(c.group, R, rx, ry, c.bn_ctx) == 1) {
                    if (BN_is_odd(ry)) BN_sub(k, c.n, k);
                    uint8_t rx_bytes[32];
                    BN_bn2binpad(rx, rx_bytes, 32);
                    uint8_t chal_in[96];
                    std::memcpy(chal_in, rx_bytes, 32);
                    std::memcpy(chal_in + 32, pub_bytes, 32);
                    std::memcpy(chal_in + 64, msg32.data(), 32);
                    std::array<uint8_t, 32> chal_h = tagged_hash("BIP0340/challenge", chal_in, 96);
                    BN_bin2bn(chal_h.data(), 32, e);
                    BN_nnmod(e, e, c.n, c.bn_ctx);
                    BN_mod_mul(s, e, d, c.n, c.bn_ctx);
                    BN_mod_add(s, k, s, c.n, c.bn_ctx);
                    std::memcpy(sig_out.data(), rx_bytes, 32);
                    BN_bn2binpad(s, sig_out.data() + 32, 32);
                    ok = true;
                }
            }
            OPENSSL_cleanse(d_bytes, sizeof(d_bytes));
        }
    }
    EC_POINT_free(R);
    EC_POINT_free(P);
    BN_clear_free(s);
    BN_clear_free(e);
    BN_clear_free(ry);
    BN_clear_free(rx);
    BN_clear_free(k);
    BN_clear_free(py);
    BN_clear_free(px);
    BN_clear_free(d);
    return ok;
}

bool bip340_verify(const std::array<uint8_t, 32>& msg32,
                   const std::array<uint8_t, 64>& sig64,
                   const std::array<uint8_t, 32>& pub_xonly32) {
    Secp256k1Ctx c;
    if (!c.ok()) return false;
    BIGNUM* px = BN_bin2bn(pub_xonly32.data(), 32, nullptr);
    BIGNUM* rx = BN_bin2bn(sig64.data(), 32, nullptr);
    BIGNUM* s = BN_bin2bn(sig64.data() + 32, 32, nullptr);
    BIGNUM* e = BN_new();
    BIGNUM* neg_e = BN_new();
    BIGNUM* res_x = BN_new();
    BIGNUM* res_y = BN_new();
    EC_POINT* P = EC_POINT_new(c.group);
    EC_POINT* R = EC_POINT_new(c.group);
    bool ok = false;

    if (px && rx && s && e && neg_e && res_x && res_y && P && R) {
        if (BN_cmp(rx, c.p) < 0 && BN_cmp(s, c.n) < 0 && lift_x(c, px, P)) {
            uint8_t chal_in[96];
            std::memcpy(chal_in, sig64.data(), 32);
            std::memcpy(chal_in + 32, pub_xonly32.data(), 32);
            std::memcpy(chal_in + 64, msg32.data(), 32);
            std::array<uint8_t, 32> chal_h = tagged_hash("BIP0340/challenge", chal_in, 96);
            BN_bin2bn(chal_h.data(), 32, e);
            BN_nnmod(e, e, c.n, c.bn_ctx);
            if (BN_is_zero(e)) {
                BN_zero(neg_e);
            } else {
                BN_sub(neg_e, c.n, e);
            }
            // R = s*G + (n - e)*P
            if (EC_POINT_mul(c.group, R, s, P, neg_e, c.bn_ctx) == 1 &&
                !EC_POINT_is_at_infinity(c.group, R) &&
                EC_POINT_get_affine_coordinates(c.group, R, res_x, res_y, c.bn_ctx) == 1) {
                ok = (!BN_is_odd(res_y) && BN_cmp(res_x, rx) == 0);
            }
        }
    }
    EC_POINT_free(R);
    EC_POINT_free(P);
    BN_free(res_y);
    BN_free(res_x);
    BN_free(neg_e);
    BN_free(e);
    BN_free(s);
    BN_free(rx);
    BN_free(px);
    return ok;
}

}  // namespace r2p
