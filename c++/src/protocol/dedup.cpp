#include "protocol/dedup.hpp"

#include <chrono>

namespace r2p {

namespace {

double wall_seconds() {
    return std::chrono::duration<double>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace

bool DedupCache::is_duplicate(const std::array<uint8_t, 6>& message_id,
                              uint16_t chunk_id,
                              double now) {
    if (chunk_id > max_chunk_id_) return true;
    double t = (now < 0.0) ? wall_seconds() : now;
    size_t byte_idx = static_cast<size_t>(chunk_id >> 3);
    uint8_t mask = static_cast<uint8_t>(1U << (chunk_id & 7));

    std::lock_guard<std::mutex> lock(mu_);
    std::map<std::array<uint8_t, 6>, std::list<Entry>::iterator>::iterator it = index_.find(message_id);
    if (it != index_.end() && (t - it->second->first_seen >= ttl_)) {
        order_.erase(it->second);
        index_.erase(it);
        it = index_.end();
    }
    if (it == index_.end()) {
        while (order_.size() >= max_ids_) {
            index_.erase(order_.front().id);
            order_.pop_front();
        }
        Entry e;
        e.id = message_id;
        e.first_seen = t;
        e.bits.assign(byte_idx + 1, 0);
        e.bits[byte_idx] = mask;
        order_.push_back(e);
        std::list<Entry>::iterator last = order_.end();
        --last;
        index_[message_id] = last;
        return false;
    }
    std::vector<uint8_t>& bits = it->second->bits;
    if (byte_idx < bits.size()) {
        if ((bits[byte_idx] & mask) != 0) return true;
        bits[byte_idx] |= mask;
        return false;
    }
    bits.resize(byte_idx + 1, 0);
    bits[byte_idx] = mask;
    return false;
}

void DedupCache::purge(double now) {
    double t = (now < 0.0) ? wall_seconds() : now;
    std::lock_guard<std::mutex> lock(mu_);
    for (std::list<Entry>::iterator it = order_.begin(); it != order_.end();) {
        if (t - it->first_seen >= ttl_) {
            index_.erase(it->id);
            it = order_.erase(it);
        } else {
            ++it;
        }
    }
}

void DedupCache::clear() {
    std::lock_guard<std::mutex> lock(mu_);
    order_.clear();
    index_.clear();
}

size_t DedupCache::size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return index_.size();
}

}  // namespace r2p
