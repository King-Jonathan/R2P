#ifndef R2P_CRYPTO_CIPHER_HPP
#define R2P_CRYPTO_CIPHER_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace r2p {

static const size_t kNonceBytes = 12;
static const size_t kAeadTagBytes = 16;

// RFC 5869 HKDF-SHA256. Empty salt uses 32 zero bytes.
bool hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len);

std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len);
std::array<uint8_t, 32> expand_body_key(const std::array<uint8_t, 16>& vibe_key);
std::array<uint8_t, 32> expand_presence_key(const std::array<uint8_t, 16>& vibe_key);

// Deterministic 64-hex-char HMAC-SHA256 Nostr filter tag (chat protocols 0 or 2).
std::string nostr_filter_tag(const std::array<uint8_t, 16>& vibe_key, uint8_t protocol);

// RFC 8439 ChaCha20-Poly1305 packet body encryption/decryption with 26-byte header AAD.
bool body_encrypt(const std::array<uint8_t, 32>& body_key,
                  const std::array<uint8_t, 6>& message_id,
                  uint16_t chunk_id,
                  const uint8_t* plaintext, size_t plain_len,
                  uint8_t protocol,
                  const uint8_t* aad, size_t aad_len,
                  std::vector<uint8_t>& out);

bool body_decrypt(const std::array<uint8_t, 32>& body_key,
                  const std::array<uint8_t, 6>& message_id,
                  uint16_t chunk_id,
                  const uint8_t* ciphertext, size_t cipher_len,
                  uint8_t protocol,
                  const uint8_t* aad, size_t aad_len,
                  std::vector<uint8_t>& out);

// Nostr presence AEAD: random 12-byte nonce || ciphertext || 16-byte tag.
bool endpoint_encrypt(const std::array<uint8_t, 32>& presence_key,
                      const uint8_t* plaintext, size_t plain_len,
                      std::vector<uint8_t>& out);

bool endpoint_encrypt_with_nonce(const std::array<uint8_t, 32>& presence_key,
                                 const std::array<uint8_t, kNonceBytes>& nonce,
                                 const uint8_t* plaintext, size_t plain_len,
                                 std::vector<uint8_t>& out);

bool endpoint_decrypt(const std::array<uint8_t, 32>& presence_key,
                      const uint8_t* ciphertext, size_t cipher_len,
                      std::vector<uint8_t>& out);

}  // namespace r2p

#endif
