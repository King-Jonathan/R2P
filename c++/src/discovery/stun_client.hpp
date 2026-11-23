#ifndef R2P_DISCOVERY_STUN_CLIENT_HPP
#define R2P_DISCOVERY_STUN_CLIENT_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "discovery/presence.hpp"

namespace r2p {

static const uint32_t kStunMagic = 0x2112A442u;
static const uint16_t kStunBindingRequest = 0x0001u;
static const uint16_t kStunBindingSuccess = 0x0101u;

void parse_host_port(const std::string& server, std::string& host, uint16_t& port,
                     uint16_t default_port = 19302);

void build_stun_binding_request(std::vector<uint8_t>& packet_out,
                                std::array<uint8_t, 12>& tx_id_out);

bool is_stun_response(const uint8_t* data, size_t len);

bool parse_stun_mapped_address(const uint8_t* data, size_t len,
                               const std::array<uint8_t, 12>* expected_tx,
                               Endpoint& out);

}  // namespace r2p

#endif
