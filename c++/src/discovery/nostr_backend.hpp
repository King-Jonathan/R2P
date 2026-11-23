#ifndef R2P_DISCOVERY_NOSTR_BACKEND_HPP
#define R2P_DISCOVERY_NOSTR_BACKEND_HPP

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "crypto/vibe.hpp"
#include "discovery/ws_client.hpp"
#include "util/json.hpp"

namespace r2p {

static const int kNostrKindEphemeral = 20001;
static const double kNostrPublishInterval = 300.0;

std::array<uint8_t, 32> nostr_event_id(const std::string& pubkey_hex,
                                       int64_t created_at,
                                       int kind,
                                       const Json& tags,
                                       const std::string& content);

Json build_nostr_event(const std::array<uint8_t, 32>& privkey,
                       const std::string& pubkey_hex,
                       int kind,
                       const Json& tags,
                       const std::string& content,
                       int64_t created_at = -1);

bool verify_nostr_event(const Json& event);

class NostrDiscoveryBackend {
public:
    typedef std::function<std::vector<uint8_t>()> GetPresenceFn;
    typedef std::function<void(const std::vector<uint8_t>&, uint8_t)> OnPresenceFn;
    typedef std::function<void(const std::string&)> OnStatusFn;

    NostrDiscoveryBackend(const std::vector<std::string>& relays,
                          VibeKeys* vibe,
                          uint8_t protocol,
                          GetPresenceFn get_presence,
                          OnPresenceFn on_presence = OnPresenceFn(),
                          OnStatusFn on_status = OnStatusFn());
    ~NostrDiscoveryBackend();

    void start();
    void stop();
    void on_vibe_changed(uint8_t protocol);
    void tick(double now);

    // Exposed for unit testing without live relays.
    std::string req_message();
    void handle_message(const std::string& raw, const std::string& url = "");
    const std::string& pubkey_hex() const { return pub_hex_; }
    const std::array<uint8_t, 32>& privkey() const { return priv_; }

private:
    void relay_loop(std::string url);
    void publisher_loop();
    void update_relays();
    void resubscribe_all();
    void publish_all();
    void handle_ok(const std::string& url, const Json& msg);
    void handle_content(const std::string& content_b64, uint8_t protocol);

    std::vector<std::string> relays_;
    VibeKeys* vibe_;
    GetPresenceFn get_presence_;
    OnPresenceFn on_presence_;
    OnStatusFn on_status_;

    std::array<uint8_t, 32> priv_;
    std::string pub_hex_;

    mutable std::mutex mu_;
    std::condition_variable wake_cv_;
    uint8_t protocol_;
    uint64_t revision_;
    double last_publish_;
    bool force_publish_;
    bool need_resub_;
    std::atomic<bool> running_;

    std::map<std::string, std::shared_ptr<WsClient> > conns_;
    std::vector<std::thread> relay_threads_;
    std::thread pub_thread_;
};

}  // namespace r2p

#endif
