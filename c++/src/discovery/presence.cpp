#include "discovery/presence.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace r2p {

namespace {

bool parse_ipv4_bytes(const std::string& host, uint8_t out[4]) {
    struct in_addr addr;
    if (inet_pton(AF_INET, host.c_str(), &addr) != 1) return false;
    std::memcpy(out, &addr.s_addr, 4);
    return true;
}

bool is_usable_ipv4(const uint8_t ip[4]) {
    if (ip[0] == 127) return false;
    if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0) return false;
    return true;
}

}  // namespace

bool is_ipv4(const std::string& host) {
    uint8_t b[4];
    return parse_ipv4_bytes(host, b);
}

bool is_private_ipv4(const std::string& host) {
    uint8_t o[4];
    if (!parse_ipv4_bytes(host, o)) return false;
    if (o[0] == 10) return true;
    if (o[0] == 192 && o[1] == 168) return true;
    if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) return true;
    return false;
}

bool shares_lan(const std::string& host, const std::set<std::string>& local_ips) {
    if (!is_private_ipv4(host)) return false;
    uint8_t hb[4];
    if (!parse_ipv4_bytes(host, hb)) return false;
    for (std::set<std::string>::const_iterator it = local_ips.begin();
         it != local_ips.end(); ++it) {
        if (!is_private_ipv4(*it)) continue;
        uint8_t lb[4];
        if (parse_ipv4_bytes(*it, lb) && hb[0] == lb[0] && hb[1] == lb[1] && hb[2] == lb[2]) {
            return true;
        }
    }
    return false;
}

std::vector<uint8_t> encode_presence(const std::array<uint8_t, kInstanceIdBytes>& instance_id,
                                     const std::vector<Endpoint>& endpoints) {
    std::vector<uint8_t> packed;
    std::set<Endpoint> seen;
    uint8_t count = 0;
    for (size_t i = 0; i < endpoints.size(); ++i) {
        if (endpoints[i].port == 0) continue;
        uint8_t ip[4];
        if (!parse_ipv4_bytes(endpoints[i].host, ip) || !is_usable_ipv4(ip)) continue;
        if (!seen.insert(endpoints[i]).second) continue;
        packed.insert(packed.end(), ip, ip + 4);
        packed.push_back(static_cast<uint8_t>((endpoints[i].port >> 8) & 0xFF));
        packed.push_back(static_cast<uint8_t>(endpoints[i].port & 0xFF));
        if (++count >= kMaxPresenceEndpoints) break;
    }
    if (count == 0) return std::vector<uint8_t>();
    std::vector<uint8_t> out;
    out.reserve(kInstanceIdBytes + 1 + packed.size());
    out.insert(out.end(), instance_id.begin(), instance_id.end());
    out.push_back(count);
    out.insert(out.end(), packed.begin(), packed.end());
    return out;
}

bool decode_presence(const uint8_t* data, size_t len,
                     std::array<uint8_t, kInstanceIdBytes>& instance_out,
                     std::vector<Endpoint>& endpoints_out) {
    endpoints_out.clear();
    if (!data || len < kInstanceIdBytes + 1) return false;
    uint8_t count = data[kInstanceIdBytes];
    if (count < 1 || count > kMaxPresenceEndpoints) return false;
    if (len != kInstanceIdBytes + 1 + static_cast<size_t>(count) * 6) return false;
    std::memcpy(instance_out.data(), data, kInstanceIdBytes);
    std::set<Endpoint> seen;
    size_t off = kInstanceIdBytes + 1;
    for (uint8_t i = 0; i < count; ++i) {
        const uint8_t* ip = data + off;
        uint16_t port = static_cast<uint16_t>((static_cast<uint16_t>(data[off + 4]) << 8) | data[off + 5]);
        off += 6;
        if (port == 0 || !is_usable_ipv4(ip)) return false;
        char buf[INET_ADDRSTRLEN];
        struct in_addr addr;
        std::memcpy(&addr.s_addr, ip, 4);
        if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) return false;
        Endpoint ep(buf, port);
        if (seen.insert(ep).second) endpoints_out.push_back(ep);
    }
    return !endpoints_out.empty();
}

bool pick_send_addr(const std::vector<Endpoint>& their_endpoints,
                    const std::string& our_public,
                    const std::set<std::string>& our_locals,
                    uint16_t our_port,
                    const std::set<Endpoint>& our_endpoints,
                    Endpoint& out) {
    std::vector<Endpoint> candidates;
    for (size_t i = 0; i < their_endpoints.size(); ++i) {
        if (our_endpoints.find(their_endpoints[i]) == our_endpoints.end()) {
            candidates.push_back(their_endpoints[i]);
        }
    }
    if (candidates.empty()) return false;

    for (size_t i = 0; i < candidates.size(); ++i) {
        if (candidates[i].port != our_port &&
            our_locals.find(candidates[i].host) != our_locals.end()) {
            out = Endpoint("127.0.0.1", candidates[i].port);
            return true;
        }
    }
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (shares_lan(candidates[i].host, our_locals)) {
            out = candidates[i];
            return true;
        }
    }
    if (!our_public.empty()) {
        bool same_nat = false;
        for (size_t i = 0; i < their_endpoints.size(); ++i) {
            if (their_endpoints[i].host == our_public) {
                same_nat = true;
                break;
            }
        }
        if (same_nat) {
            for (size_t i = 0; i < candidates.size(); ++i) {
                if (candidates[i].host != our_public && is_ipv4(candidates[i].host)) {
                    out = candidates[i];
                    return true;
                }
            }
            for (size_t i = 0; i < candidates.size(); ++i) {
                if (candidates[i].host == our_public && candidates[i].port != our_port) {
                    out = Endpoint("127.0.0.1", candidates[i].port);
                    return true;
                }
            }
        }
    }
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (candidates[i].host == our_public) continue;
        if (is_ipv4(candidates[i].host) && !is_private_ipv4(candidates[i].host)) {
            out = candidates[i];
            return true;
        }
    }
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (is_ipv4(candidates[i].host)) {
            out = candidates[i];
            return true;
        }
    }
    return false;
}

std::string primary_ipv4() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return std::string();
    struct sockaddr_in dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);
    std::string result;
    if (connect(fd, reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)) == 0) {
        struct sockaddr_in local;
        socklen_t len = sizeof(local);
        if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&local), &len) == 0) {
            uint8_t ip[4];
            std::memcpy(ip, &local.sin_addr.s_addr, 4);
            if (is_usable_ipv4(ip)) {
                char buf[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf))) {
                    result = buf;
                }
            }
        }
    }
    close(fd);
    return result;
}

std::vector<std::string> local_ipv4_addresses() {
    std::string primary = primary_ipv4();
    std::set<std::string> ips;
    if (!primary.empty()) ips.insert(primary);

    struct ifaddrs* ifa = nullptr;
    if (getifaddrs(&ifa) == 0 && ifa) {
        for (struct ifaddrs* p = ifa; p != nullptr; p = p->ifa_next) {
            if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
            if ((p->ifa_flags & IFF_UP) == 0 || (p->ifa_flags & IFF_LOOPBACK) != 0) continue;
            struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(p->ifa_addr);
            uint8_t ip[4];
            std::memcpy(ip, &sin->sin_addr.s_addr, 4);
            if (!is_usable_ipv4(ip)) continue;
            char buf[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) {
                ips.insert(buf);
            }
        }
        freeifaddrs(ifa);
    }

    std::vector<std::string> out;
    if (!primary.empty()) {
        out.push_back(primary);
        ips.erase(primary);
    }
    out.insert(out.end(), ips.begin(), ips.end());
    return out;
}

}  // namespace r2p
