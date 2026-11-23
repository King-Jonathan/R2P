#ifndef R2P_DISCOVERY_PEER_LIST_HPP
#define R2P_DISCOVERY_PEER_LIST_HPP

#include <cstddef>
#include <map>
#include <mutex>
#include <set>
#include <vector>

#include "discovery/presence.hpp"

namespace r2p {

static const size_t kMaxPeers = 64;

class PeerList {
public:
    void replace_self(const std::set<Endpoint>& endpoints);
    bool is_self(const Endpoint& ep) const;
    bool add(const Endpoint& ep, double now = -1.0);
    void clear();
    std::vector<Endpoint> all() const;
    size_t count() const;
    void purge_older_than(double max_age, double now = -1.0);

private:
    mutable std::mutex mu_;
    std::map<Endpoint, double> peers_;
    std::set<Endpoint> self_;
};

}  // namespace r2p

#endif
