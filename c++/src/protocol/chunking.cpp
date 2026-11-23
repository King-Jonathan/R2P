#include "protocol/chunking.hpp"

#include <chrono>

#include "protocol/packet.hpp"

namespace r2p {

namespace {

double wall_seconds() {
    return std::chrono::duration<double>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace

std::string truncate_utf8_chars(const std::string& s, size_t max_chars) {
    size_t chars = 0;
    size_t i = 0;
    while (i < s.size() && chars < max_chars) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t step = 1;
        if ((c & 0xE0) == 0xC0) step = 2;
        else if ((c & 0xF0) == 0xE0) step = 3;
        else if ((c & 0xF8) == 0xF0) step = 4;
        if (i + step > s.size()) break;
        i += step;
        ++chars;
    }
    return s.substr(0, i);
}

std::string build_message_body(const std::string& callsign, const std::string& message) {
    // U+00A6 broken bar in UTF-8: 0xC2 0xA6
    return truncate_utf8_chars(callsign, 16) + " \xC2\xA6 " + message;
}

bool chunk_body(const std::vector<uint8_t>& encoded,
                std::vector<std::vector<uint8_t> >& out,
                size_t max_chunk) {
    out.clear();
    if (max_chunk < 1) return false;
    if (encoded.size() > kMaxMessageBytes || encoded.size() / max_chunk > kMaxChunkId) {
        return false;
    }
    for (size_t i = 0; i <= encoded.size(); i += max_chunk) {
        size_t end = (i + max_chunk < encoded.size()) ? (i + max_chunk) : encoded.size();
        out.push_back(std::vector<uint8_t>(encoded.begin() + static_cast<ptrdiff_t>(i),
                                           encoded.begin() + static_cast<ptrdiff_t>(end)));
    }
    return true;
}

bool MessageAssembler::feed(const std::array<uint8_t, 6>& message_id,
                            uint16_t chunk_id,
                            const std::vector<uint8_t>& body,
                            std::vector<uint8_t>& out,
                            double now) {
    double t = (now < 0.0) ? wall_seconds() : now;
    if (body.size() > max_chunk_) return false;
    if (static_cast<size_t>(chunk_id) * max_chunk_ + body.size() > kMaxMessageBytes) {
        return false;
    }
    purge(t);

    std::map<std::array<uint8_t, 6>, State>::iterator it = pending_.find(message_id);
    if (it == pending_.end()) {
        if (pending_.size() >= kMaxPendingMessages) {
            std::map<std::array<uint8_t, 6>, State>::iterator oldest = pending_.begin();
            for (std::map<std::array<uint8_t, 6>, State>::iterator cur = pending_.begin();
                 cur != pending_.end(); ++cur) {
                if (cur->second.started < oldest->second.started) oldest = cur;
            }
            pending_.erase(oldest);
        }
        State st;
        st.started = t;
        it = pending_.insert(std::make_pair(message_id, st)).first;
    }

    State& st = it->second;
    if (st.chunks.find(chunk_id) != st.chunks.end()) return false;
    if (st.final_id >= 0 && static_cast<int>(chunk_id) > st.final_id) {
        pending_.erase(it);
        return false;
    }
    if (st.size + body.size() > kMaxMessageBytes) {
        pending_.erase(it);
        return false;
    }
    if (is_final_chunk(body.size(), max_chunk_)) {
        bool has_higher = !st.chunks.empty() && st.chunks.rbegin()->first > chunk_id;
        if (st.final_id >= 0 || has_higher) {
            pending_.erase(it);
            return false;
        }
        st.final_id = static_cast<int>(chunk_id);
    }
    st.chunks[chunk_id] = body;
    st.size += body.size();
    if (st.final_id >= 0 && st.chunks.size() == static_cast<size_t>(st.final_id) + 1) {
        out.clear();
        out.reserve(st.size);
        for (int i = 0; i <= st.final_id; ++i) {
            const std::vector<uint8_t>& c = st.chunks[static_cast<uint16_t>(i)];
            out.insert(out.end(), c.begin(), c.end());
        }
        pending_.erase(it);
        return true;
    }
    return false;
}

void MessageAssembler::purge(double now) {
    double t = (now < 0.0) ? wall_seconds() : now;
    for (std::map<std::array<uint8_t, 6>, State>::iterator it = pending_.begin();
         it != pending_.end();) {
        if (t - it->second.started >= kPendingTtlSeconds) {
            pending_.erase(it++);
        } else {
            ++it;
        }
    }
}

}  // namespace r2p
