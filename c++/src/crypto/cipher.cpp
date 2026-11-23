#include "crypto/cipher.hpp"

#include <cstring>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "protocol/packet.hpp"
#include "util/base64.hpp"

namespace r2p {

namespace {

static const char kPresenceAad[] = "r2p-presence-v2";
static const size_t kPresenceAadLen = 15;

bool aead_encrypt(const uint8_t key[32],
                  const uint8_t nonce[kNonceBytes],
                  const uint8_t* aad, size_t aad_len,
                  const uint8_t* plain, size_t plain_len,
                  std::vector<uint8_t>& out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    out.resize(plain_len + kAeadTagBytes);
    int len = 0;
    int fin = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(kNonceBytes), nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1) {
        ok = true;
        if (aad_len > 0) {
            ok = (EVP_EncryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_len)) == 1);
        }
        if (ok && plain_len > 0) {
            ok = (EVP_EncryptUpdate(ctx, out.data(), &len, plain, static_cast<int>(plain_len)) == 1);
        } else {
            len = 0;
        }
        if (ok) {
            uint8_t dummy = 0;
            ok = (EVP_EncryptFinal_ex(ctx, plain_len > 0 ? (out.data() + len) : &dummy, &fin) == 1);
        }
        if (ok) {
            ok = (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(kAeadTagBytes),
                                      out.data() + plain_len) == 1);
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) out.clear();
    return ok;
}

bool aead_decrypt(const uint8_t key[32],
                  const uint8_t nonce[kNonceBytes],
                  const uint8_t* aad, size_t aad_len,
                  const uint8_t* cipher_and_tag, size_t total_len,
                  std::vector<uint8_t>& out) {
    if (total_len < kAeadTagBytes) return false;
    size_t ct_len = total_len - kAeadTagBytes;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    out.resize(ct_len);
    int len = 0;
    int fin = 0;
    uint8_t tag[kAeadTagBytes];
    std::memcpy(tag, cipher_and_tag + ct_len, kAeadTagBytes);
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(kNonceBytes), nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1) {
        ok = true;
        if (aad_len > 0) {
            ok = (EVP_DecryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_len)) == 1);
        }
        if (ok && ct_len > 0) {
            ok = (EVP_DecryptUpdate(ctx, out.data(), &len, cipher_and_tag, static_cast<int>(ct_len)) == 1);
        } else {
            len = 0;
        }
        if (ok) {
            ok = (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(kAeadTagBytes), tag) == 1);
        }
        if (ok) {
            uint8_t dummy = 0;
            ok = (EVP_DecryptFinal_ex(ctx, (ct_len > 0 && static_cast<size_t>(len) < ct_len)
                                               ? (out.data() + len)
                                               : &dummy,
                                      &fin) == 1);
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) out.clear();
    return ok;
}

std::array<uint8_t, kNonceBytes> nonce_for_chunk(const std::array<uint8_t, 6>& message_id,
                                                 uint16_t chunk_id,
                                                 uint8_t protocol) {
    static const char kSuffix[] = "r2p-body-v2";
    uint8_t material[6 + 2 + 1 + 11];
    std::memcpy(material, message_id.data(), 6);
    material[6] = static_cast<uint8_t>((chunk_id >> 8) & 0xFF);
    material[7] = static_cast<uint8_t>(chunk_id & 0xFF);
    material[8] = protocol;
    std::memcpy(material + 9, kSuffix, 11);
    std::array<uint8_t, 32> digest = sha256(material, sizeof(material));
    std::array<uint8_t, kNonceBytes> nonce;
    std::memcpy(nonce.data(), digest.data(), kNonceBytes);
    return nonce;
}

}  // namespace

std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len) {
    std::array<uint8_t, 32> digest;
    SHA256(data, len, digest.data());
    return digest;
}

bool hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len) {
    if (out_len == 0 || out_len > 255 * 32) return false;
    uint8_t zero_salt[32];
    std::memset(zero_salt, 0, sizeof(zero_salt));
    const uint8_t* use_salt = (salt && salt_len > 0) ? salt : zero_salt;
    size_t use_salt_len = (salt && salt_len > 0) ? salt_len : sizeof(zero_salt);

    uint8_t prk[32];
    unsigned int prk_len = 0;
    if (!HMAC(EVP_sha256(), use_salt, static_cast<int>(use_salt_len),
              ikm, ikm_len, prk, &prk_len) || prk_len != 32) {
        return false;
    }

    uint8_t t[32];
    size_t t_len = 0;
    size_t written = 0;
    uint8_t counter = 1;
    std::vector<uint8_t> buf;
    while (written < out_len) {
        buf.clear();
        buf.insert(buf.end(), t, t + t_len);
        if (info && info_len > 0) buf.insert(buf.end(), info, info + info_len);
        buf.push_back(counter++);
        unsigned int out_n = 0;
        if (!HMAC(EVP_sha256(), prk, 32, &buf[0], buf.size(), t, &out_n) || out_n != 32) {
            return false;
        }
        t_len = 32;
        size_t take = (out_len - written < 32) ? (out_len - written) : 32;
        std::memcpy(out + written, t, take);
        written += take;
    }
    OPENSSL_cleanse(prk, sizeof(prk));
    OPENSSL_cleanse(t, sizeof(t));
    return true;
}

std::array<uint8_t, 32> expand_body_key(const std::array<uint8_t, 16>& vibe_key) {
    static const char kInfo[] = "r2p-body-v2";
    std::array<uint8_t, 32> key;
    hkdf_sha256(vibe_key.data(), 16, nullptr, 0,
                reinterpret_cast<const uint8_t*>(kInfo), 11, key.data(), 32);
    return key;
}

std::array<uint8_t, 32> expand_presence_key(const std::array<uint8_t, 16>& vibe_key) {
    static const char kInfo[] = "r2p-presence-v2";
    std::array<uint8_t, 32> key;
    hkdf_sha256(vibe_key.data(), 16, nullptr, 0,
                reinterpret_cast<const uint8_t*>(kInfo), 15, key.data(), 32);
    return key;
}

std::string nostr_filter_tag(const std::array<uint8_t, 16>& vibe_key, uint8_t protocol) {
    if (!is_chat_protocol(protocol)) return std::string();
    static const char kPrefix[] = "r2p-nostr-tag-v2:";
    uint8_t msg[18];
    std::memcpy(msg, kPrefix, 17);
    msg[17] = protocol;
    uint8_t mac[32];
    unsigned int mac_len = 0;
    if (!HMAC(EVP_sha256(), vibe_key.data(), 16, msg, sizeof(msg), mac, &mac_len) || mac_len != 32) {
        return std::string();
    }
    return hex_encode(mac, 32);
}

bool body_encrypt(const std::array<uint8_t, 32>& body_key,
                  const std::array<uint8_t, 6>& message_id,
                  uint16_t chunk_id,
                  const uint8_t* plaintext, size_t plain_len,
                  uint8_t protocol,
                  const uint8_t* aad, size_t aad_len,
                  std::vector<uint8_t>& out) {
    if (!is_valid_protocol(protocol)) return false;
    std::array<uint8_t, kNonceBytes> nonce = nonce_for_chunk(message_id, chunk_id, protocol);
    return aead_encrypt(body_key.data(), nonce.data(), aad, aad_len, plaintext, plain_len, out);
}

bool body_decrypt(const std::array<uint8_t, 32>& body_key,
                  const std::array<uint8_t, 6>& message_id,
                  uint16_t chunk_id,
                  const uint8_t* ciphertext, size_t cipher_len,
                  uint8_t protocol,
                  const uint8_t* aad, size_t aad_len,
                  std::vector<uint8_t>& out) {
    if (!is_valid_protocol(protocol)) return false;
    std::array<uint8_t, kNonceBytes> nonce = nonce_for_chunk(message_id, chunk_id, protocol);
    return aead_decrypt(body_key.data(), nonce.data(), aad, aad_len, ciphertext, cipher_len, out);
}

bool endpoint_encrypt_with_nonce(const std::array<uint8_t, 32>& presence_key,
                                 const std::array<uint8_t, kNonceBytes>& nonce,
                                 const uint8_t* plaintext, size_t plain_len,
                                 std::vector<uint8_t>& out) {
    std::vector<uint8_t> ct;
    if (!aead_encrypt(presence_key.data(), nonce.data(),
                      reinterpret_cast<const uint8_t*>(kPresenceAad), kPresenceAadLen,
                      plaintext, plain_len, ct)) {
        return false;
    }
    out.resize(kNonceBytes + ct.size());
    std::memcpy(&out[0], nonce.data(), kNonceBytes);
    std::memcpy(&out[kNonceBytes], &ct[0], ct.size());
    return true;
}

bool endpoint_encrypt(const std::array<uint8_t, 32>& presence_key,
                      const uint8_t* plaintext, size_t plain_len,
                      std::vector<uint8_t>& out) {
    std::array<uint8_t, kNonceBytes> nonce;
    if (RAND_bytes(nonce.data(), static_cast<int>(kNonceBytes)) != 1) return false;
    return endpoint_encrypt_with_nonce(presence_key, nonce, plaintext, plain_len, out);
}

bool endpoint_decrypt(const std::array<uint8_t, 32>& presence_key,
                      const uint8_t* ciphertext, size_t cipher_len,
                      std::vector<uint8_t>& out) {
    if (cipher_len < kNonceBytes + kAeadTagBytes) return false;
    return aead_decrypt(presence_key.data(), ciphertext,
                        reinterpret_cast<const uint8_t*>(kPresenceAad), kPresenceAadLen,
                        ciphertext + kNonceBytes, cipher_len - kNonceBytes, out);
}

}  // namespace r2p
