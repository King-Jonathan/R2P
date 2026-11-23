#ifndef R2P_CRYPTO_VIBE_HPP
#define R2P_CRYPTO_VIBE_HPP

#include <array>
#include <cstdint>
#include <mutex>
#include <string>

#include "protocol/packet.hpp"

namespace r2p {

static const int64_t kSlotSeconds = 300;

std::array<uint8_t, 16> normalize_16(const std::string& value);
std::array<uint8_t, 16> room_id_16(const std::string& frequency);
int64_t slot_for_time(int64_t unix_time);
int64_t current_unix_time();

std::array<uint8_t, 16> vibe_key_for_slot(const std::string& channel_key,
                                          const std::string& frequency,
                                          int64_t slot);

struct VibeSnapshot {
    int64_t slot;
    std::array<uint8_t, 16> last;
    std::array<uint8_t, 16> current;
    std::array<uint8_t, 16> next;
    std::array<uint8_t, 32> body_last;
    std::array<uint8_t, 32> body_current;
    std::array<uint8_t, 32> body_next;
    std::array<uint8_t, 32> presence_last;
    std::array<uint8_t, 32> presence_current;
    std::array<uint8_t, 32> presence_next;
    std::array<std::string, 3> tags_pixel;
    std::array<std::string, 3> tags_spec;

    std::array<std::array<uint8_t, 32>, 3> candidate_body_keys() const {
        return {{body_current, body_last, body_next}};
    }

    std::array<std::array<uint8_t, 32>, 3> candidate_presence_keys() const {
        return {{presence_current, presence_last, presence_next}};
    }

    const std::array<std::string, 3>& nostr_tags(uint8_t protocol) const {
        return (protocol == kProtocolSpectrogram) ? tags_spec : tags_pixel;
    }
};

class VibeKeys {
public:
    VibeKeys(const std::string& channel_key, const std::string& frequency);

    void set_credentials(const std::string& channel_key, const std::string& frequency);
    VibeSnapshot refresh(int64_t unix_time = -1);
    VibeSnapshot snapshot() const;
    std::array<uint8_t, 16> room_id() const;

private:
    mutable std::mutex mu_;
    std::string channel_key_;
    std::string frequency_;
    std::array<uint8_t, 16> room_id_;
    bool has_snapshot_;
    VibeSnapshot snapshot_;
};

}  // namespace r2p

#endif
