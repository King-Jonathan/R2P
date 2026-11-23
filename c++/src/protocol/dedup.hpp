#ifndef R2P_PROTOCOL_DEDUP_HPP
#define R2P_PROTOCOL_DEDUP_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <list>
#include <map>
#include <mutex>
#include <vector>

#include "protocol/chunking.hpp"

namespace r2p {

class DedupCache {
public:
    explicit DedupCache(double ttl_seconds = 600.0,
                        size_t max_ids = 4096,
                        uint16_t max_chunk_id = kMaxValidChunkId)
        : ttl_(ttl_seconds), max_ids_(max_ids), max_chunk_id_(max_chunk_id) {}

    bool is_duplicate(const std::array<uint8_t, 6>& message_id,
                      uint16_t chunk_id,
                      double now = -1.0);
    void purge(double now = -1.0);
    void clear();
    size_t size() const;

private:
    struct Entry {
        std::array<uint8_t, 6> id;
        double first_seen;
        std::vector<uint8_t> bits;
    };

    double ttl_;
    size_t max_ids_;
    uint16_t max_chunk_id_;
    mutable std::mutex mu_;
    std::list<Entry> order_;
    std::map<std::array<uint8_t, 6>, std::list<Entry>::iterator> index_;
};

}  // namespace r2p

#endif
