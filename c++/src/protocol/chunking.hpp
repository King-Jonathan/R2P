#ifndef R2P_PROTOCOL_CHUNKING_HPP
#define R2P_PROTOCOL_CHUNKING_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace r2p {

static const size_t kMaxChunkBody = 200;
static const size_t kMaxMessageBytes = 2 * 1024 * 1024;
static const uint16_t kMaxValidChunkId = static_cast<uint16_t>(kMaxMessageBytes / kMaxChunkBody);
static const size_t kMaxPendingMessages = 16;
static const double kPendingTtlSeconds = 60.0;

std::string truncate_utf8_chars(const std::string& s, size_t max_chars);
std::string build_message_body(const std::string& callsign, const std::string& message);

bool chunk_body(const std::vector<uint8_t>& encoded,
                std::vector<std::vector<uint8_t> >& out,
                size_t max_chunk = kMaxChunkBody);

inline bool is_final_chunk(size_t body_len, size_t max_chunk = kMaxChunkBody) {
    return body_len < max_chunk;
}

class MessageAssembler {
public:
    explicit MessageAssembler(size_t max_chunk = kMaxChunkBody) : max_chunk_(max_chunk) {}

    // Returns true and writes complete payload to `out` when message finishes.
    bool feed(const std::array<uint8_t, 6>& message_id,
              uint16_t chunk_id,
              const std::vector<uint8_t>& body,
              std::vector<uint8_t>& out,
              double now = -1.0);

    void purge(double now = -1.0);
    void clear() { pending_.clear(); }
    size_t pending_count() const { return pending_.size(); }

private:
    struct State {
        double started;
        std::map<uint16_t, std::vector<uint8_t> > chunks;
        int final_id;
        size_t size;
        State() : started(0.0), final_id(-1), size(0) {}
    };

    size_t max_chunk_;
    std::map<std::array<uint8_t, 6>, State> pending_;
};

}  // namespace r2p

#endif
