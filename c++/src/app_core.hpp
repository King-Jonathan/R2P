#ifndef R2P_APP_CORE_HPP
#define R2P_APP_CORE_HPP

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "config.hpp"
#include "crypto/vibe.hpp"
#include "discovery/lan_backend.hpp"
#include "discovery/nostr_backend.hpp"
#include "discovery/peer_list.hpp"
#include "discovery/presence.hpp"
#include "encoding/glyphs.hpp"
#include "encoding/spectrogram.hpp"
#include "encoding/tables.hpp"
#include "protocol/chunking.hpp"
#include "protocol/dedup.hpp"
#include "protocol/packet.hpp"
#include "transport/udp_socket.hpp"

namespace r2p {

// One message as glyphs or a spectrogram, with no received message text string.
struct LogEntry {
    uint64_t id;
    bool is_spectrogram;
    std::vector<Glyph> glyphs;
    Spectrogram spectrogram;
    double received_at;
    bool local;

    LogEntry() : id(0), is_spectrogram(false), received_at(0.0), local(false) {}
};

class AppCore {
public:
    explicit AppCore(const Config& cfg);
    ~AppCore();

    AppCore(const AppCore&) = delete;
    AppCore& operator=(const AppCore&) = delete;

    bool start();
    void stop();

    // Config & runtime controls
    Config config_snapshot() const;
    uint16_t listen_port() const { return udp_.port(); }
    uint8_t message_protocol() const;
    bool lan_enabled() const;
    bool nostr_enabled() const;
    std::string callsign() const;

    void set_callsign(const std::string& value);
    void set_frequency(const std::string& value);
    void set_channel_key(const std::string& value);
    bool set_encoding(const std::string& name);
    bool reload_encodings();
    bool set_message_mode(const std::string& name);
    void set_discovery_backend(const std::string& name);
    std::string cycle_discovery_backend();
    bool rebind_udp(uint16_t port, uint16_t& bound_out);

    // Chat & discovery
    bool send_chat(const std::string& message, std::string& error_out);
    void publish_lan_discovery();
    bool ingest_presence(const std::vector<uint8_t>& raw, Endpoint& added_out);
    std::vector<uint8_t> get_presence_bytes() const;

    // UI state queries
    uint64_t log_version() const;
    std::vector<LogEntry> log_entries() const;
    size_t peer_count() const { return peers_.count(); }
    std::string current_status() const;
    void status(const std::string& msg);

    // Helpers exposed for tests
    void add_peer(const Endpoint& ep) { peers_.add(ep); }
    std::vector<Endpoint> all_peers() const { return peers_.all(); }
    void inject_udp(const uint8_t* data, size_t len, const Endpoint& addr) {
        on_udp(data, len, addr);
    }
    VibeKeys& vibe() { return vibe_; }
    const std::array<uint8_t, kInstanceIdBytes>& instance_id() const { return instance_id_; }
    uint64_t room_epoch() const;

private:
    void build_backends_locked();
    void retune();
    void notify_vibe();
    void timer_loop();
    void start_stun_async();
    void stun_worker();
    void refresh_local_ips();
    void remember_self_endpoints();
    std::vector<Endpoint> our_endpoints() const;
    std::set<std::string> local_ips_set() const;
    std::string combine_status(const std::string& extra) const;

    void on_nostr_presence(const std::vector<uint8_t>& raw, uint8_t protocol);
    void on_nostr_status(const std::string& msg);
    void on_udp(const uint8_t* data, size_t len, const Endpoint& addr);
    bool decrypt_body(const Packet& pkt, std::vector<uint8_t>& plain_out);
    void handle_discovery_body(const std::vector<uint8_t>& plain, const Endpoint& addr);
    bool build_discovery_packet(Packet& out);
    void send_packet_twice(const Packet& pkt, const std::vector<Endpoint>& peers, double delay_s = 0.0);
    std::vector<Endpoint> broadcast_peers() const;
    void append_log_locked(const LogEntry& entry);
    void clear_log_locked();

    mutable std::recursive_mutex mu_;
    Config cfg_;
    VibeKeys vibe_;
    PeerList peers_;
    DedupCache dedup_;
    MessageAssembler assembler_;
    std::map<std::string, EncodingTables> encodings_;
    EncodingTables tables_;
    std::deque<LogEntry> log_;
    uint64_t log_version_;
    uint64_t next_log_id_;
    uint64_t room_epoch_;
    std::deque<std::array<uint8_t, 6> > recent_tx_ids_;
    std::string callsign_;
    std::array<uint8_t, kInstanceIdBytes> instance_id_;
    std::vector<std::string> cached_local_ips_;
    std::string public_ip_;
    uint16_t public_port_;

    mutable std::mutex status_mu_;
    std::string status_box_;
    std::string net_status_;
    std::string nostr_status_;

    UdpTransport udp_;
    std::shared_ptr<NostrDiscoveryBackend> nostr_;
    std::shared_ptr<LanDiscoveryBackend> lan_;

    std::atomic<bool> started_;
    std::atomic<bool> stop_flag_;
    std::mutex timer_mu_;
    std::condition_variable timer_cv_;
    std::thread timer_thread_;
    std::mutex stun_launch_mu_;
    std::thread stun_thread_;
    int64_t last_slot_;
};

}  // namespace r2p

#endif
