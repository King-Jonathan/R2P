#ifndef R2P_PROTOCOL_PACKET_HPP
#define R2P_PROTOCOL_PACKET_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace r2p {

static const uint8_t kProtocolPixel = 0;
static const uint8_t kProtocolDiscovery = 1;
static const uint8_t kProtocolSpectrogram = 2;

static const size_t kHeaderBytes = 26;
static const size_t kPadMin = 200;
static const size_t kPadMax = 300;
static const size_t kMaxBody = 255;
static const uint16_t kMaxChunkId = 65535;

inline bool is_valid_protocol(uint8_t p) {
    return p == kProtocolPixel || p == kProtocolDiscovery || p == kProtocolSpectrogram;
}

inline bool is_chat_protocol(uint8_t p) {
    return p == kProtocolPixel || p == kProtocolSpectrogram;
}

struct Packet {
    uint8_t protocol;
    std::array<uint8_t, 16> room_id;
    std::array<uint8_t, 6> message_id;
    uint16_t chunk_id;
    std::vector<uint8_t> body;

    Packet() : protocol(0), room_id(), message_id(), chunk_id(0) {}
};

// Pack the 26-byte wire header (also used as AEAD AAD).
bool pack_header(uint8_t protocol,
                 const std::array<uint8_t, 16>& room_id,
                 const std::array<uint8_t, 6>& message_id,
                 uint16_t chunk_id,
                 size_t body_len,
                 std::array<uint8_t, kHeaderBytes>& out);

bool packet_aad(const Packet& pkt, std::array<uint8_t, kHeaderBytes>& out);
bool pack_header_and_body(const Packet& pkt, std::vector<uint8_t>& out);

// Pack and append random padding to [200, 300] bytes (or exact pad_to if > 0).
bool pack_packet(const Packet& pkt, std::vector<uint8_t>& out, size_t pad_to = 0);
bool unpack_packet(const uint8_t* data, size_t len, Packet& out);
bool unpack_packet(const std::vector<uint8_t>& data, Packet& out);

std::array<uint8_t, 6> new_message_id();

}  // namespace r2p

#endif
