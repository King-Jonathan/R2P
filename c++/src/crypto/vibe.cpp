#include "crypto/vibe.hpp"

#include <cstring>
#include <ctime>

#include "crypto/cipher.hpp"

namespace r2p {

std::array<uint8_t, 16> normalize_16(const std::string& value) {
    std::array<uint8_t, 16> out;
    out.fill(0);
    if (value.size() <= 16) {
        if (!value.empty()) std::memcpy(out.data(), value.data(), value.size());
        return out;
    }
    std::array<uint8_t, 32> h = sha256(reinterpret_cast<const uint8_t*>(value.data()), value.size());
    std::memcpy(out.data(), h.data(), 16);
    return out;
}

std::array<uint8_t, 16> room_id_16(const std::string& frequency) {
    std::array<uint8_t, 16> norm = normalize_16(frequency);
    std::array<uint8_t, 32> h = sha256(norm.data(), 16);
    std::array<uint8_t, 16> out;
    std::memcpy(out.data(), h.data(), 16);
    return out;
}

int64_t current_unix_time() {
    return static_cast<int64_t>(std::time(nullptr));
}

int64_t slot_for_time(int64_t unix_time) {
    int64_t t = (unix_time < 0) ? current_unix_time() : unix_time;
    return (t / kSlotSeconds) * kSlotSeconds;
}

std::array<uint8_t, 16> vibe_key_for_slot(const std::string& channel_key,
                                          const std::string& frequency,
                                          int64_t slot) {
    std::array<uint8_t, 16> ck = normalize_16(channel_key);
    std::array<uint8_t, 16> freq = normalize_16(frequency);
    uint8_t salt[8];
    uint64_t uslot = static_cast<uint64_t>(slot);
    for (int i = 7; i >= 0; --i) {
        salt[i] = static_cast<uint8_t>(uslot & 0xFF);
        uslot >>= 8;
    }
    static const char kPrefix[] = "r2p-vibe-v2";
    uint8_t info[11 + 16];
    std::memcpy(info, kPrefix, 11);
    std::memcpy(info + 11, freq.data(), 16);
    std::array<uint8_t, 16> out;
    hkdf_sha256(ck.data(), 16, salt, 8, info, sizeof(info), out.data(), 16);
    return out;
}

static VibeSnapshot build_snapshot(const std::string& channel_key,
                                   const std::string& frequency,
                                   int64_t slot) {
    VibeSnapshot s;
    s.slot = slot;
    s.last = vibe_key_for_slot(channel_key, frequency, slot - kSlotSeconds);
    s.current = vibe_key_for_slot(channel_key, frequency, slot);
    s.next = vibe_key_for_slot(channel_key, frequency, slot + kSlotSeconds);
    s.body_last = expand_body_key(s.last);
    s.body_current = expand_body_key(s.current);
    s.body_next = expand_body_key(s.next);
    s.presence_last = expand_presence_key(s.last);
    s.presence_current = expand_presence_key(s.current);
    s.presence_next = expand_presence_key(s.next);
    s.tags_pixel[0] = nostr_filter_tag(s.last, kProtocolPixel);
    s.tags_pixel[1] = nostr_filter_tag(s.current, kProtocolPixel);
    s.tags_pixel[2] = nostr_filter_tag(s.next, kProtocolPixel);
    s.tags_spec[0] = nostr_filter_tag(s.last, kProtocolSpectrogram);
    s.tags_spec[1] = nostr_filter_tag(s.current, kProtocolSpectrogram);
    s.tags_spec[2] = nostr_filter_tag(s.next, kProtocolSpectrogram);
    return s;
}

VibeKeys::VibeKeys(const std::string& channel_key, const std::string& frequency)
    : channel_key_(channel_key),
      frequency_(frequency),
      room_id_(room_id_16(frequency)),
      has_snapshot_(false) {
    refresh();
}

void VibeKeys::set_credentials(const std::string& channel_key, const std::string& frequency) {
    std::lock_guard<std::mutex> lock(mu_);
    channel_key_ = channel_key;
    frequency_ = frequency;
    room_id_ = room_id_16(frequency);
    has_snapshot_ = false;
    snapshot_ = build_snapshot(channel_key_, frequency_, slot_for_time(-1));
    has_snapshot_ = true;
}

VibeSnapshot VibeKeys::refresh(int64_t unix_time) {
    std::lock_guard<std::mutex> lock(mu_);
    int64_t slot = slot_for_time(unix_time);
    if (has_snapshot_ && snapshot_.slot == slot) {
        return snapshot_;
    }
    snapshot_ = build_snapshot(channel_key_, frequency_, slot);
    has_snapshot_ = true;
    return snapshot_;
}

VibeSnapshot VibeKeys::snapshot() const {
    std::lock_guard<std::mutex> lock(mu_);
    return snapshot_;
}

std::array<uint8_t, 16> VibeKeys::room_id() const {
    std::lock_guard<std::mutex> lock(mu_);
    return room_id_;
}

}  // namespace r2p
