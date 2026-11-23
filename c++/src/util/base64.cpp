#include "util/base64.hpp"

#include <cstring>

namespace r2p {

std::string hex_encode(const uint8_t* data, size_t len) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = kHex[data[i] >> 4];
        out[i * 2 + 1] = kHex[data[i] & 0x0F];
    }
    return out;
}

std::string hex_encode(const std::vector<uint8_t>& data) {
    return data.empty() ? std::string() : hex_encode(&data[0], data.size());
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool hex_decode(const std::string& hex, std::vector<uint8_t>& out) {
    if ((hex.size() & 1U) != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hex_nibble(hex[i]);
        int lo = hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

std::string base64_encode(const uint8_t* data, size_t len) {
    static const char kTab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= len) {
        uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i + 1]) << 8) |
                     static_cast<uint32_t>(data[i + 2]);
        out.push_back(kTab[(v >> 18) & 0x3F]);
        out.push_back(kTab[(v >> 12) & 0x3F]);
        out.push_back(kTab[(v >> 6) & 0x3F]);
        out.push_back(kTab[v & 0x3F]);
        i += 3;
    }
    if (i < len) {
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) v |= static_cast<uint32_t>(data[i + 1]) << 8;
        out.push_back(kTab[(v >> 18) & 0x3F]);
        out.push_back(kTab[(v >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? kTab[(v >> 6) & 0x3F] : '=');
        out.push_back('=');
    }
    return out;
}

std::string base64_encode(const std::vector<uint8_t>& data) {
    return data.empty() ? std::string() : base64_encode(&data[0], data.size());
}

static int b64_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool base64_decode(const std::string& text, std::vector<uint8_t>& out) {
    out.clear();
    if (text.empty()) return true;
    if ((text.size() & 3U) != 0) return false;
    out.reserve((text.size() / 4) * 3);
    for (size_t i = 0; i < text.size(); i += 4) {
        bool pad2 = (text[i + 2] == '=');
        bool pad3 = (text[i + 3] == '=');
        if ((pad2 || pad3) && (i + 4 != text.size())) return false;
        if (pad2 && !pad3) return false;
        int a = b64_val(static_cast<unsigned char>(text[i]));
        int b = b64_val(static_cast<unsigned char>(text[i + 1]));
        int c = pad2 ? 0 : b64_val(static_cast<unsigned char>(text[i + 2]));
        int d = pad3 ? 0 : b64_val(static_cast<unsigned char>(text[i + 3]));
        if (a < 0 || b < 0 || c < 0 || d < 0) return false;
        out.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
        if (!pad2) out.push_back(static_cast<uint8_t>(((b & 0x0F) << 4) | (c >> 2)));
        if (!pad3) out.push_back(static_cast<uint8_t>(((c & 0x03) << 6) | d));
    }
    return true;
}

}  // namespace r2p
