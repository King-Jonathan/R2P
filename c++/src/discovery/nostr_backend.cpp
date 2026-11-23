#include "discovery/nostr_backend.hpp"

#include <chrono>
#include <cstring>

#include "crypto/bip340.hpp"
#include "crypto/cipher.hpp"
#include "discovery/presence.hpp"
#include "protocol/packet.hpp"
#include "util/base64.hpp"

namespace r2p {

namespace {

double wall_seconds() {
    return std::chrono::duration<double>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string relay_host(const std::string& url) {
    size_t pos = url.find("://");
    size_t start = (pos == std::string::npos) ? 0 : pos + 3;
    size_t slash = url.find('/', start);
    std::string h = (slash == std::string::npos) ? url.substr(start) : url.substr(start, slash - start);
    return h.empty() ? "relay" : h;
}

}  // namespace

std::array<uint8_t, 32> nostr_event_id(const std::string& pubkey_hex,
                                       int64_t created_at,
                                       int kind,
                                       const Json& tags,
                                       const std::string& content) {
    Json arr = Json::make_array();
    arr.push(Json::make_int(0));
    arr.push(Json::make_string(pubkey_hex));
    arr.push(Json::make_int(created_at));
    arr.push(Json::make_int(kind));
    arr.push(tags);
    arr.push(Json::make_string(content));
    std::string raw = arr.dump_compact();
    return sha256(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
}

Json build_nostr_event(const std::array<uint8_t, 32>& privkey,
                       const std::string& pubkey_hex,
                       int kind,
                       const Json& tags,
                       const std::string& content,
                       int64_t created_at) {
    int64_t ts = (created_at < 0) ? current_unix_time() : created_at;
    std::array<uint8_t, 32> eid = nostr_event_id(pubkey_hex, ts, kind, tags, content);
    std::array<uint8_t, 64> sig;
    bip340_sign(eid, privkey, sig);

    Json ev = Json::make_object();
    ev.set("id", Json::make_string(hex_encode(eid.data(), 32)));
    ev.set("pubkey", Json::make_string(pubkey_hex));
    ev.set("created_at", Json::make_int(ts));
    ev.set("kind", Json::make_int(kind));
    ev.set("tags", tags);
    ev.set("content", Json::make_string(content));
    ev.set("sig", Json::make_string(hex_encode(sig.data(), 64)));
    return ev;
}

bool verify_nostr_event(const Json& event) {
    if (!event.is_object()) return false;
    const Json* pub = event.get("pubkey");
    const Json* kind = event.get("kind");
    const Json* ts = event.get("created_at");
    const Json* tags = event.get("tags");
    const Json* content = event.get("content");
    const Json* ev_id = event.get("id");
    const Json* sig = event.get("sig");
    if (!pub || !pub->is_string() || !ev_id || !ev_id->is_string() || !sig || !sig->is_string()) {
        return false;
    }
    if (!kind || !kind->is_int() || !ts || !ts->is_int()) return false;
    if (!tags || !tags->is_array() || !content || !content->is_string()) return false;

    std::vector<uint8_t> got_v, sig_v, pub_v;
    if (!hex_decode(ev_id->as_string(), got_v) || got_v.size() != 32) return false;
    if (!hex_decode(sig->as_string(), sig_v) || sig_v.size() != 64) return false;
    if (!hex_decode(pub->as_string(), pub_v) || pub_v.size() != 32) return false;

    std::array<uint8_t, 32> want =
        nostr_event_id(pub->as_string(), ts->as_int(), static_cast<int>(kind->as_int()),
                       *tags, content->as_string());
    if (std::memcmp(want.data(), got_v.data(), 32) != 0) return false;

    std::array<uint8_t, 64> sig64;
    std::array<uint8_t, 32> pub32;
    std::memcpy(sig64.data(), sig_v.data(), 64);
    std::memcpy(pub32.data(), pub_v.data(), 32);
    return bip340_verify(want, sig64, pub32);
}

NostrDiscoveryBackend::NostrDiscoveryBackend(const std::vector<std::string>& relays,
                                             VibeKeys* vibe,
                                             uint8_t protocol,
                                             GetPresenceFn get_presence,
                                             OnPresenceFn on_presence,
                                             OnStatusFn on_status)
    : relays_(relays),
      vibe_(vibe),
      get_presence_(get_presence),
      on_presence_(on_presence),
      on_status_(on_status),
      protocol_(protocol),
      revision_(0),
      last_publish_(0.0),
      force_publish_(true),
      need_resub_(false),
      running_(false) {
    std::array<uint8_t, 32> pub;
    bip340_generate_keypair(priv_, pub);
    pub_hex_ = hex_encode(pub.data(), 32);
}

NostrDiscoveryBackend::~NostrDiscoveryBackend() {
    stop();
}

void NostrDiscoveryBackend::start() {
    if (running_.exchange(true)) return;
    {
        std::lock_guard<std::mutex> lock(mu_);
        force_publish_ = true;
        last_publish_ = 0.0;
    }
    pub_thread_ = std::thread(&NostrDiscoveryBackend::publisher_loop, this);
    for (size_t i = 0; i < relays_.size(); ++i) {
        relay_threads_.push_back(std::thread(&NostrDiscoveryBackend::relay_loop, this, relays_[i]));
    }
}

void NostrDiscoveryBackend::stop() {
    if (!running_.exchange(false)) return;
    std::vector<std::shared_ptr<WsClient> > to_close;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (std::map<std::string, std::shared_ptr<WsClient> >::iterator it = conns_.begin();
             it != conns_.end(); ++it) {
            to_close.push_back(it->second);
        }
        conns_.clear();
    }
    for (size_t i = 0; i < to_close.size(); ++i) {
        to_close[i]->shutdown_io();
    }
    wake_cv_.notify_all();
    if (pub_thread_.joinable()) pub_thread_.join();
    for (size_t i = 0; i < relay_threads_.size(); ++i) {
        if (relay_threads_[i].joinable()) relay_threads_[i].join();
    }
    relay_threads_.clear();
}

void NostrDiscoveryBackend::on_vibe_changed(uint8_t protocol) {
    if (!is_chat_protocol(protocol)) return;
    {
        std::lock_guard<std::mutex> lock(mu_);
        protocol_ = protocol;
        ++revision_;
        need_resub_ = true;
        force_publish_ = true;
        last_publish_ = 0.0;
    }
    wake_cv_.notify_one();
}

void NostrDiscoveryBackend::tick(double now) {
    if (!running_.load()) return;
    bool wake = false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!conns_.empty() && (force_publish_ || (now - last_publish_ >= kNostrPublishInterval))) {
            wake = true;
        }
    }
    if (wake) wake_cv_.notify_one();
}

std::string NostrDiscoveryBackend::req_message() {
    VibeSnapshot snap = vibe_->refresh();
    uint8_t proto = kProtocolPixel;
    {
        std::lock_guard<std::mutex> lock(mu_);
        proto = protocol_;
    }
    const std::array<std::string, 3>& tags = snap.nostr_tags(proto);
    Json t_arr = Json::make_array();
    for (size_t i = 0; i < 3; ++i) t_arr.push(Json::make_string(tags[i]));
    Json kinds = Json::make_array();
    kinds.push(Json::make_int(kNostrKindEphemeral));
    Json filt = Json::make_object();
    filt.set("kinds", kinds);
    filt.set("#t", t_arr);

    Json req = Json::make_array();
    req.push(Json::make_string("REQ"));
    req.push(Json::make_string("r2p"));
    req.push(filt);
    return req.dump_compact();
}

void NostrDiscoveryBackend::publisher_loop() {
    while (running_.load()) {
        {
            std::unique_lock<std::mutex> lock(mu_);
            wake_cv_.wait(lock, [this]() {
                if (!running_.load()) return true;
                if (conns_.empty()) return false;
                return need_resub_ || force_publish_ ||
                       (wall_seconds() - last_publish_ >= kNostrPublishInterval);
            });
        }
        if (!running_.load()) break;
        update_relays();
    }
}

void NostrDiscoveryBackend::update_relays() {
    bool do_resub = false;
    bool do_pub = false;
    {
        std::lock_guard<std::mutex> lock(mu_);
        do_resub = need_resub_;
        need_resub_ = false;
        do_pub = force_publish_ || (wall_seconds() - last_publish_ >= kNostrPublishInterval);
    }
    if (do_resub) resubscribe_all();
    if (do_pub) publish_all();
}

void NostrDiscoveryBackend::resubscribe_all() {
    std::string close_msg = "[\"CLOSE\",\"r2p\"]";
    std::string req = req_message();
    std::vector<std::shared_ptr<WsClient> > list;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (std::map<std::string, std::shared_ptr<WsClient> >::iterator it = conns_.begin();
             it != conns_.end(); ++it) {
            list.push_back(it->second);
        }
    }
    for (size_t i = 0; i < list.size(); ++i) {
        list[i]->send_text(close_msg);
        list[i]->send_text(req);
    }
}

void NostrDiscoveryBackend::publish_all() {
    std::vector<uint8_t> presence = get_presence_ ? get_presence_() : std::vector<uint8_t>();
    if (presence.empty()) return;

    std::vector<std::shared_ptr<WsClient> > list;
    uint8_t proto = kProtocolPixel;
    uint64_t rev = 0;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (std::map<std::string, std::shared_ptr<WsClient> >::iterator it = conns_.begin();
             it != conns_.end(); ++it) {
            list.push_back(it->second);
        }
        proto = protocol_;
        rev = revision_;
        if (list.empty()) {
            force_publish_ = true;
            return;
        }
    }

    VibeSnapshot snap = vibe_->refresh();
    std::vector<uint8_t> cipher;
    if (!endpoint_encrypt(snap.presence_current, presence.data(), presence.size(), cipher)) return;
    std::string content = base64_encode(cipher);
    const std::array<std::string, 3>& slot_tags = snap.nostr_tags(proto);
    Json tags = Json::make_array();
    for (size_t i = 0; i < 3; ++i) {
        Json t = Json::make_array();
        t.push(Json::make_string("t"));
        t.push(Json::make_string(slot_tags[i]));
        tags.push(t);
    }
    Json ev = build_nostr_event(priv_, pub_hex_, kNostrKindEphemeral, tags, content);
    Json frame = Json::make_array();
    frame.push(Json::make_string("EVENT"));
    frame.push(ev);
    std::string payload = frame.dump_compact();

    bool sent = false;
    for (size_t i = 0; i < list.size(); ++i) {
        if (list[i]->send_text(payload)) sent = true;
    }
    if (sent) {
        std::lock_guard<std::mutex> lock(mu_);
        if (revision_ == rev) {
            last_publish_ = wall_seconds();
            force_publish_ = false;
        }
    }
}

void NostrDiscoveryBackend::relay_loop(std::string url) {
    while (running_.load()) {
        std::shared_ptr<WsClient> ws(new WsClient());
        if (ws->connect(url, 8000)) {
            bool need_pub = false;
            {
                std::lock_guard<std::mutex> lock(mu_);
                conns_[url] = ws;
                need_pub = force_publish_ || last_publish_ <= 0.0;
            }
            ws->send_text(req_message());
            if (need_pub) wake_cv_.notify_one();

            std::string raw;
            while (running_.load() && ws->is_open()) {
                int r = ws->recv_text(raw, 1000);
                if (r == 1) {
                    handle_message(raw, url);
                } else if (r < 0) {
                    break;
                }
            }
            ws->close();
            {
                std::lock_guard<std::mutex> lock(mu_);
                std::map<std::string, std::shared_ptr<WsClient> >::iterator it = conns_.find(url);
                if (it != conns_.end() && it->second == ws) conns_.erase(it);
            }
        }
        // Sleep up to 3 seconds in small steps so stop() returns promptly.
        for (int i = 0; i < 30 && running_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

void NostrDiscoveryBackend::handle_message(const std::string& raw, const std::string& url) {
    Json msg;
    if (!Json::parse(raw, msg) || !msg.is_array() || msg.as_array().size() < 2) return;
    const std::vector<Json>& arr = msg.as_array();
    if (!arr[0].is_string()) return;
    const std::string& type = arr[0].as_string();
    if (type == "OK") {
        handle_ok(url, msg);
        return;
    }
    if (type == "NOTICE") {
        if (on_status_ && arr[1].is_string() && !arr[1].as_string().empty()) {
            on_status_("nostr notice " + relay_host(url));
        }
        return;
    }
    if (type != "EVENT" || arr.size() < 3 || !arr[2].is_object()) return;
    const Json& event = arr[2];
    const Json* kind = event.get("kind");
    const Json* pub = event.get("pubkey");
    const Json* tags = event.get("tags");
    const Json* content = event.get("content");
    if (!kind || !kind->is_int() || kind->as_int() != kNostrKindEphemeral) return;
    if (!pub || !pub->is_string() || pub->as_string() == pub_hex_) return;
    if (!tags || !tags->is_array() || !content || !content->is_string()) return;

    VibeSnapshot snap = vibe_->refresh();
    uint8_t proto = kProtocolPixel;
    {
        std::lock_guard<std::mutex> lock(mu_);
        proto = protocol_;
    }
    const std::array<std::string, 3>& allowed = snap.nostr_tags(proto);
    bool matched = false;
    const std::vector<Json>& tlist = tags->as_array();
    for (size_t i = 0; i < tlist.size(); ++i) {
        if (!tlist[i].is_array() || tlist[i].as_array().size() < 2) continue;
        const std::vector<Json>& item = tlist[i].as_array();
        if (item[0].is_string() && item[0].as_string() == "t" && item[1].is_string()) {
            const std::string& val = item[1].as_string();
            if (val == allowed[0] || val == allowed[1] || val == allowed[2]) {
                matched = true;
                break;
            }
        }
    }
    if (!matched) return;
    if (!verify_nostr_event(event)) return;
    handle_content(content->as_string(), proto);
}

void NostrDiscoveryBackend::handle_ok(const std::string& url, const Json& msg) {
    const std::vector<Json>& arr = msg.as_array();
    if (arr.size() < 3 || !arr[2].is_bool()) return;
    bool accepted = arr[2].as_bool();
    if (on_status_) {
        on_status_((accepted ? "nostr ok " : "nostr reject ") + relay_host(url));
    }
}

void NostrDiscoveryBackend::handle_content(const std::string& content_b64, uint8_t protocol) {
    std::vector<uint8_t> cipher;
    if (!base64_decode(content_b64, cipher)) return;
    std::array<std::array<uint8_t, 32>, 3> keys = vibe_->refresh().candidate_presence_keys();
    for (size_t i = 0; i < 3; ++i) {
        std::vector<uint8_t> plain;
        if (!endpoint_decrypt(keys[i], cipher.data(), cipher.size(), plain)) continue;
        std::array<uint8_t, kInstanceIdBytes> inst;
        std::vector<Endpoint> eps;
        if (!decode_presence(plain.data(), plain.size(), inst, eps)) continue;
        if (on_presence_) on_presence_(plain, protocol);
        return;
    }
}

}  // namespace r2p
