#include "discovery/stun_client.hpp"

#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <openssl/rand.h>

namespace r2p {

namespace {

uint16_t read_u16_be(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t read_u32_be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

}  // namespace

void parse_host_port(const std::string& server, std::string& host, uint16_t& port,
                     uint16_t default_port) {
    size_t colon = server.rfind(':');
    if (colon == std::string::npos) {
        host = server;
        port = default_port;
        return;
    }
    host = server.substr(0, colon);
    long p = std::strtol(server.substr(colon + 1).c_str(), nullptr, 10);
    port = (p >= 1 && p <= 65535) ? static_cast<uint16_t>(p) : default_port;
}

void build_stun_binding_request(std::vector<uint8_t>& packet_out,
                                std::array<uint8_t, 12>& tx_id_out) {
    RAND_bytes(tx_id_out.data(), 12);
    packet_out.resize(20);
    packet_out[0] = static_cast<uint8_t>((kStunBindingRequest >> 8) & 0xFF);
    packet_out[1] = static_cast<uint8_t>(kStunBindingRequest & 0xFF);
    packet_out[2] = 0;
    packet_out[3] = 0;
    packet_out[4] = static_cast<uint8_t>((kStunMagic >> 24) & 0xFF);
    packet_out[5] = static_cast<uint8_t>((kStunMagic >> 16) & 0xFF);
    packet_out[6] = static_cast<uint8_t>((kStunMagic >> 8) & 0xFF);
    packet_out[7] = static_cast<uint8_t>(kStunMagic & 0xFF);
    std::memcpy(&packet_out[8], tx_id_out.data(), 12);
}

bool is_stun_response(const uint8_t* data, size_t len) {
    if (!data || len < 20) return false;
    return read_u16_be(data) == kStunBindingSuccess && read_u32_be(data + 4) == kStunMagic;
}

bool parse_stun_mapped_address(const uint8_t* data, size_t len,
                               const std::array<uint8_t, 12>* expected_tx,
                               Endpoint& out) {
    if (!is_stun_response(data, len)) return false;
    if (expected_tx && std::memcmp(data + 8, expected_tx->data(), 12) != 0) return false;

    uint16_t msg_len = read_u16_be(data + 2);
    size_t end = 20 + static_cast<size_t>(msg_len);
    if (end > len) end = len;
    size_t off = 20;
    while (off + 4 <= end) {
        uint16_t atype = read_u16_be(data + off);
        uint16_t alen = read_u16_be(data + off + 2);
        off += 4;
        if (off + alen > end) break;
        const uint8_t* val = data + off;
        off += alen + ((4 - (alen % 4)) % 4);
        if ((atype == 0x0020 || atype == 0x0001) && alen >= 8 && val[1] == 0x01) {
            uint16_t raw_port = read_u16_be(val + 2);
            uint32_t raw_ip = read_u32_be(val + 4);
            uint16_t port = (atype == 0x0020)
                                ? static_cast<uint16_t>(raw_port ^ (kStunMagic >> 16))
                                : raw_port;
            uint32_t ip_h = (atype == 0x0020) ? (raw_ip ^ kStunMagic) : raw_ip;
            struct in_addr addr;
            addr.s_addr = htonl(ip_h);
            char buf[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) && port > 0) {
                out = Endpoint(buf, port);
                return true;
            }
        }
    }
    return false;
}

}  // namespace r2p
