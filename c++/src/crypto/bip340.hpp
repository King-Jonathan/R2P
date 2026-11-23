#ifndef R2P_CRYPTO_BIP340_HPP
#define R2P_CRYPTO_BIP340_HPP

#include <array>
#include <cstdint>

namespace r2p {

// Constant-time BIP-340 Schnorr over secp256k1 using OpenSSL EC/BN.
bool bip340_generate_keypair(std::array<uint8_t, 32>& priv_out,
                             std::array<uint8_t, 32>& pub_xonly_out);

bool bip340_sign(const std::array<uint8_t, 32>& msg32,
                 const std::array<uint8_t, 32>& priv32,
                 std::array<uint8_t, 64>& sig_out);

bool bip340_verify(const std::array<uint8_t, 32>& msg32,
                   const std::array<uint8_t, 64>& sig64,
                   const std::array<uint8_t, 32>& pub_xonly32);

}  // namespace r2p

#endif
