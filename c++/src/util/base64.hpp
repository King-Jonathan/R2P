#ifndef R2P_UTIL_BASE64_HPP
#define R2P_UTIL_BASE64_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace r2p {

std::string hex_encode(const uint8_t* data, size_t len);
std::string hex_encode(const std::vector<uint8_t>& data);
bool hex_decode(const std::string& hex, std::vector<uint8_t>& out);

std::string base64_encode(const uint8_t* data, size_t len);
std::string base64_encode(const std::vector<uint8_t>& data);
bool base64_decode(const std::string& text, std::vector<uint8_t>& out);

}  // namespace r2p

#endif
