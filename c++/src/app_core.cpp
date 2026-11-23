#include "app_core.hpp"

#include <algorithm>
#include <chrono>
#include <openssl/rand.h>

#include "crypto/cipher.hpp"
#include "encoding/spectrogram_tx.hpp"

namespace r2p {

namespace {

double wall_seconds() {
    return std::chrono::duration<double>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

double random_jitter_seconds() {
    uint32_t r = 0;
    RAND_bytes(reinterpret_cast<unsigned char*>(&r), sizeof(r));
    double frac = static_cast<double>(r) / static_cast<double>(0xFFFFFFFFu);
    return 0.005 + frac * 0.015;  // uniform 5..20 ms
}

}  // namespace

AppCore::AppCore(const Config& cfg)
    : cfg_(cfg),
      vibe_(cfg.channel_key, cfg.frequency),
      dedup_(600.0),
      assembler_(kMaxChunkBody),
      log_version_(0),
      next_log_id_(1),
      room_epoch_(0),
      callsign_(truncate_utf8_chars(cfg.default_callsign, 16)),
      cached_local_ips_(local_ipv4_addresses()),
      public_port_(0),
      status_box_("boot"),
      udp_(cfg.udp_port),
      started_(false),
      stop_flag_(true),
      last_slot_(vibe_.refresh().slot) {
    RAND_bytes(instance_id_.data(), static_cast<int>(kInstanceIdBytes));
    reload_encodings();
    udp_.set_handler([this](const uint8_t* data, size_t len, const Endpoint& addr) {
        on_udp(data, len, addr);
    });
    udp_.set_error_handler([this](const std::string& msg) { status(msg); });
    std::lock_guard<std::recursive_mutex> lock(mu_);
    build_backends_locked();
}

AppCore::~AppCore() {
    stop();
}

void AppCore::build_backends_locked() {
    std::shared_ptr<NostrDiscoveryBackend> new_nostr;
    std::shared_ptr<LanDiscoveryBackend> new_lan;
    if (cfg_.discovery_backend == "nostr" || cfg_.discovery_backend == "both") {
        new_nostr.reset(new NostrDiscoveryBackend(
            cfg_.nostr_relays,
            &vibe_,
            message_protocol(),
            [this]() { return get_presence_bytes(); },
            [this](const std::vector<uint8_t>& raw, uint8_t proto) { on_nostr_presence(raw, proto); },
            [this](const std::string& msg) { on_nostr_status(msg); }));
    }
    if (cfg_.discovery_backend == "lan" || cfg_.discovery_backend == "both") {
        new_lan.reset(new LanDiscoveryBackend([this]() { publish_lan_discovery(); }));
    }
    nostr_ = new_nostr;
    lan_ = new_lan;
}

bool AppCore::start() {
    if (!udp_.start()) {
        status("UDP bind failed");
        return false;
    }
    refresh_local_ips();
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        public_ip_.clear();
        public_port_ = 0;
    }
    remember_self_endpoints();

    std::shared_ptr<NostrDiscoveryBackend> nb;
    std::shared_ptr<LanDiscoveryBackend> lb;
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        nb = nostr_;
        lb = lan_;
    }
    if (nb) nb->start();
    if (lb) lb->start();

    stop_flag_.store(false);
    started_.store(true);
    timer_thread_ = std::thread(&AppCore::timer_loop, this);
    if (nostr_enabled()) {
        start_stun_async();
    }

    uint16_t pref = cfg_.udp_port;
    uint16_t bound = udp_.port();
    std::string net = "online :" + std::to_string(bound);
    if (bound != pref) {
        net += " (preferred " + std::to_string(pref) + " busy)";
    }
    {
        std::lock_guard<std::mutex> sl(status_mu_);
        net_status_ = net;
    }
    status(net);
    return true;
}

void AppCore::stop() {
    started_.store(false);
    stop_flag_.store(true);
    timer_cv_.notify_all();

    std::shared_ptr<NostrDiscoveryBackend> nb;
    std::shared_ptr<LanDiscoveryBackend> lb;
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        nb = nostr_;
        lb = lan_;
    }
    if (nb) nb->stop();
    if (lb) lb->stop();
    udp_.stop();
    if (timer_thread_.joinable()) timer_thread_.join();
    {
        std::lock_guard<std::mutex> sl(stun_launch_mu_);
        if (stun_thread_.joinable()) stun_thread_.join();
    }
}

void AppCore::start_stun_async() {
    std::lock_guard<std::mutex> sl(stun_launch_mu_);
    if (stun_thread_.joinable()) stun_thread_.join();
    stun_thread_ = std::thread(&AppCore::stun_worker, this);
}

Config AppCore::config_snapshot() const {
    std::lock_guard<std::recursive_mutex> lock(mu_);
    return cfg_;
}

uint8_t AppCore::message_protocol() const {
    std::lock_guard<std::recursive_mutex> lock(mu_);
    return (cfg_.message_mode == "spectrogram") ? kProtocolSpectrogram : kProtocolPixel;
}

bool AppCore::lan_enabled() const {
    std::lock_guard<std::recursive_mutex> lock(mu_);
    return cfg_.discovery_backend == "lan" || cfg_.discovery_backend == "both";
}

bool AppCore::nostr_enabled() const {
    std::lock_guard<std::recursive_mutex> lock(mu_);
    return cfg_.discovery_backend == "nostr" || cfg_.discovery_backend == "both";
}

std::string AppCore::callsign() const {
    std::lock_guard<std::recursive_mutex> lock(mu_);
    return callsign_;
}

uint64_t AppCore::room_epoch() const {
    std::lock_guard<std::recursive_mutex> lock(mu_);
    return room_epoch_;
}

void AppCore::set_callsign(const std::string& value) {
    std::lock_guard<std::recursive_mutex> lock(mu_);
    callsign_ = truncate_utf8_chars(value, 16);
    cfg_.default_callsign = callsign_;
}

void AppCore::set_frequency(const std::string& value) {
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        cfg_.frequency = value;
    }
    retune();
}

void AppCore::set_channel_key(const std::string& value) {
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        cfg_.channel_key = value;
    }
    retune();
}

void AppCore::retune() {
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        ++room_epoch_;
        udp_.discard_sends(message_protocol());
        vibe_.set_credentials(cfg_.channel_key, cfg_.frequency);
        clear_log_locked();
        assembler_.clear();
        peers_.clear();
    }
    notify_vibe();
}

bool AppCore::set_encoding(const std::string& name) {
    std::lock_guard<std::recursive_mutex> lock(mu_);
    std::map<std::string, EncodingTables>::const_iterator it = encodings_.find(name);
    if (it == encodings_.end()) return false;
    cfg_.encoding = name;
    tables_ = it->second;
    return true;
}

bool AppCore::reload_encodings() {
    std::map<std::string, EncodingTables> loaded;
    std::string path;
    std::string active;
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        path = cfg_.encodings_path;
        active = cfg_.encoding;
    }
    if (!load_encodings(path, loaded)) return false;
    std::lock_guard<std::recursive_mutex> lock(mu_);
    encodings_ = loaded;
    std::map<std::string, EncodingTables>::const_iterator it = encodings_.find(active);
    tables_ = (it != encodings_.end()) ? it->second : encodings_.begin()->second;
    return true;
}

bool AppCore::set_message_mode(const std::string& name) {
    if (name != "pixel" && name != "spectrogram") return false;
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        if (name == cfg_.message_mode) return true;
        ++room_epoch_;
        udp_.discard_sends(message_protocol());
        cfg_.message_mode = name;
        clear_log_locked();
        assembler_.clear();
        peers_.clear();
    }
    notify_vibe();
    return true;
}

void AppCore::set_discovery_backend(const std::string& name) {
    if (name != "nostr" && name != "lan" && name != "both") return;
    std::shared_ptr<NostrDiscoveryBackend> old_n;
    std::shared_ptr<LanDiscoveryBackend> old_l;
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        if (name == cfg_.discovery_backend) return;
        old_n = nostr_;
        old_l = lan_;
        nostr_.reset();
        lan_.reset();
    }
    if (old_n) old_n->stop();
    if (old_l) old_l->stop();

    std::shared_ptr<NostrDiscoveryBackend> new_n;
    std::shared_ptr<LanDiscoveryBackend> new_l;
    bool need_stun = false;
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        cfg_.discovery_backend = name;
        if (!nostr_enabled()) {
            public_ip_.clear();
            public_port_ = 0;
            {
                std::lock_guard<std::mutex> sl(status_mu_);
                nostr_status_.clear();
            }
            remember_self_endpoints();
        }
        build_backends_locked();
        new_n = nostr_;
        new_l = lan_;
        need_stun = started_.load() && nostr_enabled() && public_port_ == 0;
    }
    if (started_.load()) {
        if (new_n) new_n->start();
        if (new_l) new_l->start();
        if (need_stun) {
            start_stun_async();
        }
        notify_vibe();
    }
}

std::string AppCore::cycle_discovery_backend() {
    std::string cur;
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        cur = cfg_.discovery_backend;
    }
    std::string nxt = "nostr";
    if (cur == "nostr") nxt = "both";
    else if (cur == "both") nxt = "lan";
    else nxt = "nostr";
    set_discovery_backend(nxt);
    return nxt;
}

bool AppCore::rebind_udp(uint16_t port, uint16_t& bound_out) {
    if (!udp_.rebind(port)) {
        bound_out = udp_.port();
        return false;
    }
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        cfg_.udp_port = port;
        public_port_ = 0;
    }
    refresh_local_ips();
    remember_self_endpoints();
    if (nostr_enabled()) {
        start_stun_async();
    }
    notify_vibe();
    bound_out = udp_.port();
    return true;
}

uint64_t AppCore::log_version() const {
    std::lock_guard<std::recursive_mutex> lock(mu_);
    return log_version_;
}

std::vector<LogEntry> AppCore::log_entries() const {
    std::lock_guard<std::recursive_mutex> lock(mu_);
    return std::vector<LogEntry>(log_.begin(), log_.end());
}

std::string AppCore::current_status() const {
    std::lock_guard<std::mutex> sl(status_mu_);
    return status_box_;
}

void AppCore::status(const std::string& msg) {
    std::lock_guard<std::mutex> sl(status_mu_);
    status_box_ = msg;
}

std::string AppCore::combine_status(const std::string& extra) const {
    std::lock_guard<std::mutex> sl(status_mu_);
    if (!extra.empty() && !net_status_.empty()) {
        return net_status_ + " | " + extra;
    }
    return !extra.empty() ? extra : net_status_;
}

void AppCore::on_nostr_status(const std::string& msg) {
    {
        std::lock_guard<std::mutex> sl(status_mu_);
        nostr_status_ = msg;
    }
    status(combine_status(msg));
}

void AppCore::notify_vibe() {
    uint8_t proto = kProtocolPixel;
    std::shared_ptr<NostrDiscoveryBackend> nb;
    std::shared_ptr<LanDiscoveryBackend> lb;
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        last_slot_ = vibe_.refresh().slot;
        proto = message_protocol();
        nb = nostr_;
        lb = lan_;
    }
    if (nb) nb->on_vibe_changed(proto);
    if (lb) lb->on_vibe_changed(proto);
}

void AppCore::timer_loop() {
    while (!stop_flag_.load()) {
        {
            std::unique_lock<std::mutex> tl(timer_mu_);
            timer_cv_.wait_for(tl, std::chrono::seconds(1),
                               [this]() { return stop_flag_.load(); });
        }
        if (stop_flag_.load()) break;
        double now = wall_seconds();
        VibeSnapshot snap = vibe_.refresh(static_cast<int64_t>(now));
        bool slot_changed = false;
        {
            std::lock_guard<std::recursive_mutex> lock(mu_);
            slot_changed = (snap.slot != last_slot_);
        }
        if (slot_changed) {
            refresh_local_ips();
            remember_self_endpoints();
            notify_vibe();
        }
        dedup_.purge(now);
        peers_.purge_older_than(3600.0, now);
        std::shared_ptr<NostrDiscoveryBackend> nb;
        std::shared_ptr<LanDiscoveryBackend> lb;
        {
            std::lock_guard<std::recursive_mutex> lock(mu_);
            assembler_.purge(now);
            nb = nostr_;
            lb = lan_;
        }
        if (nb) nb->tick(now);
        if (lb) lb->tick(now);
    }
}

void AppCore::stun_worker() {
    std::string server;
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        server = cfg_.stun_server;
    }
    Endpoint mapped;
    bool ok = udp_.stun_query(server, mapped, 2.0);
    if (!started_.load() || !nostr_enabled()) return;
    std::string net;
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        if (ok) {
            public_ip_ = mapped.host;
            public_port_ = mapped.port;
            net = "public " + public_ip_ + ":" + std::to_string(public_port_);
        } else {
            public_ip_.clear();
            public_port_ = 0;
            std::string shown = !cached_local_ips_.empty() ? cached_local_ips_[0] : "127.0.0.1";
            net = "local " + shown + ":" + std::to_string(udp_.port());
        }
    }
    {
        std::lock_guard<std::mutex> sl(status_mu_);
        net_status_ = net;
    }
    remember_self_endpoints();
    std::string ns;
    {
        std::lock_guard<std::mutex> sl(status_mu_);
        ns = nostr_status_;
    }
    status(combine_status(ns));
    notify_vibe();
}

void AppCore::refresh_local_ips() {
    std::vector<std::string> ips = local_ipv4_addresses();
    std::lock_guard<std::recursive_mutex> lock(mu_);
    cached_local_ips_ = ips;
}

std::set<std::string> AppCore::local_ips_set() const {
    std::lock_guard<std::recursive_mutex> lock(mu_);
    return std::set<std::string>(cached_local_ips_.begin(), cached_local_ips_.end());
}

std::vector<Endpoint> AppCore::our_endpoints() const {
    std::lock_guard<std::recursive_mutex> lock(mu_);
    uint16_t listen = udp_.port() ? udp_.port() : cfg_.udp_port;
    uint16_t pub_port = public_port_ ? public_port_ : listen;
    std::vector<Endpoint> out;
    std::set<Endpoint> seen;
    if (!public_ip_.empty()) {
        Endpoint ep(public_ip_, pub_port);
        out.push_back(ep);
        seen.insert(ep);
    }
    for (size_t i = 0; i < cached_local_ips_.size(); ++i) {
        Endpoint ep(cached_local_ips_[i], listen);
        if (seen.insert(ep).second) out.push_back(ep);
    }
    return out;
}

void AppCore::remember_self_endpoints() {
    std::lock_guard<std::recursive_mutex> lock(mu_);
    uint16_t listen = udp_.port() ? udp_.port() : cfg_.udp_port;
    std::set<Endpoint> eps;
    eps.insert(Endpoint("127.0.0.1", listen));
    for (size_t i = 0; i < cached_local_ips_.size(); ++i) {
        eps.insert(Endpoint(cached_local_ips_[i], listen));
    }
    std::vector<Endpoint> ours = our_endpoints();
    eps.insert(ours.begin(), ours.end());
    peers_.replace_self(eps);
}

std::vector<uint8_t> AppCore::get_presence_bytes() const {
    std::vector<Endpoint> eps = our_endpoints();
    if (eps.empty()) {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        uint16_t listen = udp_.port() ? udp_.port() : cfg_.udp_port;
        if (!cached_local_ips_.empty()) {
            eps.push_back(Endpoint(cached_local_ips_[0], listen));
        }
    }
    if (eps.empty()) return std::vector<uint8_t>();
    return encode_presence(instance_id_, eps);
}

void AppCore::on_nostr_presence(const std::vector<uint8_t>& raw, uint8_t protocol) {
    std::lock_guard<std::recursive_mutex> lock(mu_);
    if (protocol != message_protocol()) return;
    Endpoint addr;
    if (ingest_presence(raw, addr)) {
        Packet pkt;
        if (build_discovery_packet(pkt)) {
            std::vector<Endpoint> one(1, addr);
            send_packet_twice(pkt, one);
        }
    }
}

bool AppCore::ingest_presence(const std::vector<uint8_t>& raw, Endpoint& added_out) {
    std::array<uint8_t, kInstanceIdBytes> inst;
    std::vector<Endpoint> eps;
    if (!decode_presence(raw.data(), raw.size(), inst, eps)) return false;
    if (inst == instance_id_) return false;

    std::string our_pub;
    uint16_t listen = 0;
    std::set<std::string> locals;
    std::set<Endpoint> our_eps;
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        our_pub = public_ip_;
        listen = udp_.port();
        locals = local_ips_set();
        std::vector<Endpoint> oe = our_endpoints();
        our_eps.insert(oe.begin(), oe.end());
        our_eps.insert(Endpoint("127.0.0.1", listen));
    }
    Endpoint chosen;
    if (!pick_send_addr(eps, our_pub, locals, listen, our_eps, chosen)) return false;
    if (peers_.add(chosen)) {
        added_out = chosen;
        return true;
    }
    return false;
}

bool AppCore::send_chat(const std::string& message, std::string& error_out) {
    error_out.clear();
    uint64_t epoch = 0;
    std::string cs;
    uint8_t proto = kProtocolPixel;
    EncodingTables tbl;
    std::array<uint8_t, 16> room;
    std::array<uint8_t, 32> body_key;
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        epoch = room_epoch_;
        cs = callsign_;
        proto = message_protocol();
        tbl = tables_;
        room = vibe_.room_id();
        body_key = vibe_.refresh().body_current;
    }

    std::string text = build_message_body(cs, message);
    std::vector<uint8_t> encoded;
    LogEntry entry;
    entry.local = true;
    entry.received_at = wall_seconds();

    if (proto == kProtocolPixel) {
        encoded = encode_text(tbl, text);
        entry.is_spectrogram = false;
        entry.glyphs = codes_to_glyphs(tbl, encoded);
        if (encoded.empty() || entry.glyphs.empty()) return true;
    } else {
        if (!text_to_audio(text, encoded, error_out)) return false;
        entry.is_spectrogram = true;
        if (!audio_to_spectrogram(encoded, entry.spectrogram)) {
            error_out = "spectrogram decode failed";
            return false;
        }
    }

    std::vector<std::vector<uint8_t> > chunks;
    if (!chunk_body(encoded, chunks, kMaxChunkBody)) {
        error_out = "message is too large";
        return false;
    }

    std::array<uint8_t, 6> mid = new_message_id();
    std::vector<Packet> packets;
    packets.reserve(chunks.size());
    for (size_t i = 0; i < chunks.size(); ++i) {
        uint16_t cid = static_cast<uint16_t>(i);
        std::array<uint8_t, kHeaderBytes> aad;
        if (!pack_header(proto, room, mid, cid, chunks[i].size() + kAeadTagBytes, aad)) {
            error_out = "packet header failed";
            return false;
        }
        std::vector<uint8_t> ct;
        if (!body_encrypt(body_key, mid, cid,
                          chunks[i].empty() ? nullptr : chunks[i].data(), chunks[i].size(),
                          proto, aad.data(), aad.size(), ct)) {
            error_out = "encryption failed";
            return false;
        }
        Packet pkt;
        pkt.protocol = proto;
        pkt.room_id = room;
        pkt.message_id = mid;
        pkt.chunk_id = cid;
        pkt.body = ct;
        packets.push_back(pkt);
    }

    std::lock_guard<std::recursive_mutex> lock(mu_);
    if (room_epoch_ != epoch) return true;
    append_log_locked(entry);
    recent_tx_ids_.push_back(mid);
    while (recent_tx_ids_.size() > 64) recent_tx_ids_.pop_front();
    std::vector<Endpoint> peers = peers_.all();
    if (peers.empty()) return true;
    for (size_t i = 0; i < packets.size(); ++i) {
        send_packet_twice(packets[i], peers, static_cast<double>(i) * 0.002);
    }
    return true;
}

void AppCore::publish_lan_discovery() {
    Packet pkt;
    if (build_discovery_packet(pkt)) {
        send_packet_twice(pkt, broadcast_peers());
    }
}

bool AppCore::build_discovery_packet(Packet& out) {
    std::vector<uint8_t> plain = get_presence_bytes();
    if (plain.empty()) return false;
    std::array<uint8_t, 6> mid = new_message_id();
    std::array<uint8_t, 16> room = vibe_.room_id();
    std::array<uint8_t, 32> body_key = vibe_.refresh().body_current;
    std::array<uint8_t, kHeaderBytes> aad;
    if (!pack_header(kProtocolDiscovery, room, mid, 0, plain.size() + kAeadTagBytes, aad)) {
        return false;
    }
    std::vector<uint8_t> ct;
    if (!body_encrypt(body_key, mid, 0, plain.data(), plain.size(),
                      kProtocolDiscovery, aad.data(), aad.size(), ct)) {
        return false;
    }
    out.protocol = kProtocolDiscovery;
    out.room_id = room;
    out.message_id = mid;
    out.chunk_id = 0;
    out.body = ct;
    return true;
}

void AppCore::send_packet_twice(const Packet& pkt, const std::vector<Endpoint>& peers, double delay_s) {
    if (peers.empty()) return;
    std::vector<uint8_t> copy_a, copy_b;
    if (!pack_packet(pkt, copy_a) || !pack_packet(pkt, copy_b)) return;
    double delay_b = delay_s + random_jitter_seconds();
    for (size_t i = 0; i < peers.size(); ++i) {
        udp_.enqueue_send(copy_a, peers[i], delay_s);
        udp_.enqueue_send(copy_b, peers[i], delay_b);
    }
}

std::vector<Endpoint> AppCore::broadcast_peers() const {
    std::vector<uint16_t> ports = udp_.broadcast_ports();
    std::vector<Endpoint> out;
    out.reserve(ports.size());
    for (size_t i = 0; i < ports.size(); ++i) {
        out.push_back(Endpoint("255.255.255.255", ports[i]));
    }
    return out;
}

bool AppCore::decrypt_body(const Packet& pkt, std::vector<uint8_t>& plain_out) {
    std::array<uint8_t, kHeaderBytes> aad;
    if (!packet_aad(pkt, aad)) return false;
    std::array<std::array<uint8_t, 32>, 3> keys = vibe_.refresh().candidate_body_keys();
    for (size_t i = 0; i < 3; ++i) {
        if (body_decrypt(keys[i], pkt.message_id, pkt.chunk_id,
                         pkt.body.data(), pkt.body.size(),
                         pkt.protocol, aad.data(), aad.size(), plain_out)) {
            return true;
        }
    }
    return false;
}

void AppCore::handle_discovery_body(const std::vector<uint8_t>& plain, const Endpoint& addr) {
    std::array<uint8_t, kInstanceIdBytes> inst;
    std::vector<Endpoint> eps;
    if (!decode_presence(plain.data(), plain.size(), inst, eps)) return;
    if (inst == instance_id_) return;
    std::set<std::string> locals = local_ips_set();
    Endpoint ret = (locals.count(addr.host) && addr.port != udp_.port())
                       ? Endpoint("127.0.0.1", addr.port)
                       : addr;
    if (!peers_.is_self(ret)) {
        peers_.add(ret);
        return;
    }
    Endpoint ignored;
    ingest_presence(plain, ignored);
}

void AppCore::on_udp(const uint8_t* data, size_t len, const Endpoint& addr) {
    Packet pkt;
    if (!unpack_packet(data, len, pkt) || pkt.chunk_id > kMaxValidChunkId) return;

    uint64_t epoch = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        epoch = room_epoch_;
        if (pkt.room_id != vibe_.room_id()) return;
        if (pkt.protocol != kProtocolDiscovery && pkt.protocol != message_protocol()) return;
    }

    std::vector<uint8_t> plain;
    if (!decrypt_body(pkt, plain)) return;

    bool has_complete = false;
    std::vector<uint8_t> complete;
    EncodingTables tbl;
    {
        std::lock_guard<std::recursive_mutex> lock(mu_);
        if (room_epoch_ != epoch) return;
        if (dedup_.is_duplicate(pkt.message_id, pkt.chunk_id)) return;
        if (pkt.protocol == kProtocolDiscovery) {
            handle_discovery_body(plain, addr);
            return;
        }
        if (std::find(recent_tx_ids_.begin(), recent_tx_ids_.end(), pkt.message_id) !=
            recent_tx_ids_.end()) {
            return;
        }
        has_complete = assembler_.feed(pkt.message_id, pkt.chunk_id, plain, complete);
        tbl = tables_;
    }

    bool have_entry = false;
    LogEntry entry;
    if (has_complete) {
        entry.local = false;
        entry.received_at = wall_seconds();
        if (pkt.protocol == kProtocolPixel) {
            entry.is_spectrogram = false;
            entry.glyphs = codes_to_glyphs(tbl, complete);
            have_entry = !entry.glyphs.empty();
        } else {
            entry.is_spectrogram = true;
            have_entry = audio_to_spectrogram(complete, entry.spectrogram);
        }
    }

    std::lock_guard<std::recursive_mutex> lock(mu_);
    if (room_epoch_ != epoch) return;
    if (have_entry) append_log_locked(entry);
    if (!peers_.is_self(addr)) peers_.add(addr);
}

void AppCore::append_log_locked(const LogEntry& entry) {
    LogEntry copy = entry;
    copy.id = next_log_id_++;
    log_.push_back(copy);
    while (static_cast<int>(log_.size()) > cfg_.visible_lines) {
        log_.pop_front();
    }
    ++log_version_;
}

void AppCore::clear_log_locked() {
    log_.clear();
    ++log_version_;
}

}  // namespace r2p
