#ifndef R2P_DISCOVERY_PRESENCE_HPP
#define R2P_DISCOVERY_PRESENCE_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace r2p {

static const size_t kInstanceIdBytes = 8;
static const size_t kMaxPresenceEndpoints = 8;

struct Endpoint {
    std::string host;
    uint16_t port;

    Endpoint() : port(0) {}
    Endpoint(const std::string& h, uint16_t p) : host(h), port(p) {}

    bool operator==(const Endpoint& o) const { return port == o.port && host == o.host; }
    bool operator!=(const Endpoint& o) const { return !(*this == o); }
    bool operator<(const Endpoint& o) const {
        return host < o.host || (host == o.host && port < o.port);
    }
};

bool is_ipv4(const std::string& host);
bool is_private_ipv4(const std::string& host);
bool shares_lan(const std::string& host, const std::set<std::string>& local_ips);

// Binary presence: instance_id(8) || count(1) || count*(ipv4(4)+port_be(2)).
std::vector<uint8_t> encode_presence(const std::array<uint8_t, kInstanceIdBytes>& instance_id,
                                     const std::vector<Endpoint>& endpoints);

bool decode_presence(const uint8_t* data, size_t len,
                     std::array<uint8_t, kInstanceIdBytes>& instance_out,
                     std::vector<Endpoint>& endpoints_out);

bool pick_send_addr(const std::vector<Endpoint>& their_endpoints,
                    const std::string& our_public,
                    const std::set<std::string>& our_locals,
                    uint16_t our_port,
                    const std::set<Endpoint>& our_endpoints,
                    Endpoint& out);

std::string primary_ipv4();
std::vector<std::string> local_ipv4_addresses();

}  // namespace r2p

#endif
