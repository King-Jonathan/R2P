#include "protocol/packet.hpp"

#include <cstring>
#include <openssl/rand.h>

namespace r2p {

bool pack_header(uint8_t protocol,
                 const std::array<uint8_t, 16>& room_id,
                 const std::array<uint8_t, 6>& message_id,
                 uint16_t chunk_id,
                 size_t body_len,
                 std::array<uint8_t, kHeaderBytes>& out) {
    if (!is_valid_protocol(protocol) || body_len > kMaxBody) return false;
    out[0] = protocol;
    std::memcpy(&out[1], room_id.data(), 16);
    std::memcpy(&out[17], message_id.data(), 6);
    out[23] = static_cast<uint8_t>((chunk_id >> 8) & 0xFF);
    out[24] = static_cast<uint8_t>(chunk_id & 0xFF);
    out[25] = static_cast<uint8_t>(body_len);
    return true;
}

bool packet_aad(const Packet& pkt, std::array<uint8_t, kHeaderBytes>& out) {
    return pack_header(pkt.protocol, pkt.room_id, pkt.message_id, pkt.chunk_id, pkt.body.size(), out);
}

bool pack_header_and_body(const Packet& pkt, std::vector<uint8_t>& out) {
    std::array<uint8_t, kHeaderBytes> hdr;
    if (!packet_aad(pkt, hdr)) return false;
    out.resize(kHeaderBytes + pkt.body.size());
    std::memcpy(&out[0], hdr.data(), kHeaderBytes);
    if (!pkt.body.empty()) {
        std::memcpy(&out[kHeaderBytes], &pkt.body[0], pkt.body.size());
    }
    return true;
}

static size_t random_in_range(size_t lo, size_t hi) {
    if (lo >= hi) return lo;
    uint32_t span = static_cast<uint32_t>(hi - lo + 1);
    uint32_t limit = (0xFFFFFFFFu / span) * span;
    uint32_t r = 0;
    do {
        RAND_bytes(reinterpret_cast<unsigned char*>(&r), sizeof(r));
    } while (r >= limit);
    return lo + (r % span);
}

bool pack_packet(const Packet& pkt, std::vector<uint8_t>& out, size_t pad_to) {
    std::vector<uint8_t> core;
    if (!pack_header_and_body(pkt, core)) return false;
    if (core.size() > kPadMax) return false;
    if (pad_to == 0) {
        size_t lo = core.size() > kPadMin ? core.size() : kPadMin;
        pad_to = random_in_range(lo, kPadMax);
    }
    if (pad_to < core.size() || pad_to > kPadMax) return false;
    out.resize(pad_to);
    std::memcpy(&out[0], &core[0], core.size());
    size_t pad_len = pad_to - core.size();
    if (pad_len > 0) {
        if (RAND_bytes(&out[core.size()], static_cast<int>(pad_len)) != 1) return false;
    }
    return true;
}

bool unpack_packet(const uint8_t* data, size_t len, Packet& out) {
    if (!data || len < kPadMin || len > kPadMax || len < kHeaderBytes) return false;
    uint8_t proto = data[0];
    if (!is_valid_protocol(proto)) return false;
    uint8_t body_len = data[25];
    size_t end = kHeaderBytes + static_cast<size_t>(body_len);
    if (end > len) return false;
    out.protocol = proto;
    std::memcpy(out.room_id.data(), data + 1, 16);
    std::memcpy(out.message_id.data(), data + 17, 6);
    out.chunk_id = static_cast<uint16_t>((static_cast<uint16_t>(data[23]) << 8) | data[24]);
    out.body.assign(data + kHeaderBytes, data + end);
    return true;
}

bool unpack_packet(const std::vector<uint8_t>& data, Packet& out) {
    return data.empty() ? false : unpack_packet(&data[0], data.size(), out);
}

std::array<uint8_t, 6> new_message_id() {
    std::array<uint8_t, 6> mid;
    RAND_bytes(mid.data(), 6);
    return mid;
}

}  // namespace r2p
