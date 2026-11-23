#include "discovery/peer_list.hpp"

#include <chrono>

namespace r2p {

namespace {

double wall_seconds() {
    return std::chrono::duration<double>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace

void PeerList::replace_self(const std::set<Endpoint>& endpoints) {
    std::lock_guard<std::mutex> lock(mu_);
    self_ = endpoints;
}

bool PeerList::is_self(const Endpoint& ep) const {
    std::lock_guard<std::mutex> lock(mu_);
    return self_.find(ep) != self_.end();
}

bool PeerList::add(const Endpoint& ep, double now) {
    double t = (now < 0.0) ? wall_seconds() : now;
    std::lock_guard<std::mutex> lock(mu_);
    if (self_.find(ep) != self_.end()) return false;
    bool existed = (peers_.find(ep) != peers_.end());
    peers_[ep] = t;
    while (peers_.size() > kMaxPeers) {
        std::map<Endpoint, double>::iterator oldest = peers_.begin();
        for (std::map<Endpoint, double>::iterator it = peers_.begin(); it != peers_.end(); ++it) {
            if (it->second < oldest->second) oldest = it;
        }
        peers_.erase(oldest);
    }
    return !existed;
}

void PeerList::clear() {
    std::lock_guard<std::mutex> lock(mu_);
    peers_.clear();
}

std::vector<Endpoint> PeerList::all() const {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<Endpoint> out;
    out.reserve(peers_.size());
    for (std::map<Endpoint, double>::const_iterator it = peers_.begin();
         it != peers_.end(); ++it) {
        out.push_back(it->first);
    }
    return out;
}

size_t PeerList::count() const {
    std::lock_guard<std::mutex> lock(mu_);
    return peers_.size();
}

void PeerList::purge_older_than(double max_age, double now) {
    double t = (now < 0.0) ? wall_seconds() : now;
    std::lock_guard<std::mutex> lock(mu_);
    for (std::map<Endpoint, double>::iterator it = peers_.begin(); it != peers_.end();) {
        if (t - it->second > max_age) {
            peers_.erase(it++);
        } else {
            ++it;
        }
    }
}

}  // namespace r2p
