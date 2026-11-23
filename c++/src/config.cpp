#include "config.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

#include "protocol/chunking.hpp"
#include "util/json.hpp"

namespace r2p {

namespace {

std::string lower_trim(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    std::string out = s.substr(a, b - a);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(out[i])));
    }
    return out;
}

}  // namespace

Config::Config()
    : default_callsign("Booperator"),
      frequency("7.074"),
      channel_key("liberty"),
      udp_port(19302),
      visible_lines(20),
      encoding("default"),
      message_mode("pixel"),
      stun_server("stun.l.google.com:19302"),
      discovery_backend("nostr"),
      encodings_path("encodings.json"),
      config_path("config.json") {
    nostr_relays.push_back("wss://relay.damus.io");
    nostr_relays.push_back("wss://nos.lol");
    nostr_relays.push_back("wss://relay.nostr.band");
}

bool load_config(const std::string& path, Config& out) {
    out = Config();
    out.config_path = path;
    std::ifstream fh(path.c_str(), std::ios::binary);
    if (!fh) return true;  // Missing file -> defaults.
    std::ostringstream ss;
    ss << fh.rdbuf();
    Json root;
    if (!Json::parse(ss.str(), root) || !root.is_object()) return false;

    const Json* v = nullptr;
    if ((v = root.get("default_callsign")) && v->is_string()) {
        out.default_callsign = truncate_utf8_chars(v->as_string(), 16);
    }
    if ((v = root.get("frequency")) && v->is_string()) out.frequency = v->as_string();
    if ((v = root.get("channel_key")) && v->is_string()) out.channel_key = v->as_string();
    if ((v = root.get("udp_port")) && v->is_int()) {
        int64_t p = v->as_int();
        if (p >= 1 && p <= 65535) out.udp_port = static_cast<uint16_t>(p);
    }
    if ((v = root.get("visible_lines")) && v->is_int() && v->as_int() >= 1) {
        out.visible_lines = static_cast<int>(v->as_int());
    }
    if ((v = root.get("encoding")) && v->is_string()) out.encoding = v->as_string();
    if ((v = root.get("message_mode")) && v->is_string()) {
        std::string m = lower_trim(v->as_string());
        if (m != "pixel" && m != "spectrogram") return false;
        out.message_mode = m;
    }
    if ((v = root.get("nostr_relays")) && v->is_array()) {
        std::vector<std::string> relays;
        const std::vector<Json>& arr = v->as_array();
        bool all_str = true;
        for (size_t i = 0; i < arr.size(); ++i) {
            if (!arr[i].is_string()) {
                all_str = false;
                break;
            }
            relays.push_back(arr[i].as_string());
        }
        if (all_str) out.nostr_relays = relays;
    }
    if ((v = root.get("stun_server")) && v->is_string()) out.stun_server = v->as_string();
    if ((v = root.get("discovery_backend")) && v->is_string()) {
        std::string b = lower_trim(v->as_string());
        if (b == "nostr" || b == "lan" || b == "both") out.discovery_backend = b;
    }
    if ((v = root.get("encodings_path")) && v->is_string()) out.encodings_path = v->as_string();
    return true;
}

bool save_config(const Config& cfg, const std::string& path_override) {
    std::string target = path_override.empty() ? cfg.config_path : path_override;
    Json obj = Json::make_object();
    obj.set("default_callsign", Json::make_string(truncate_utf8_chars(cfg.default_callsign, 16)));
    obj.set("frequency", Json::make_string(cfg.frequency));
    obj.set("channel_key", Json::make_string(cfg.channel_key));
    obj.set("udp_port", Json::make_int(cfg.udp_port));
    obj.set("visible_lines", Json::make_int(cfg.visible_lines));
    obj.set("encoding", Json::make_string(cfg.encoding));
    obj.set("message_mode", Json::make_string(cfg.message_mode));
    Json relays = Json::make_array();
    for (size_t i = 0; i < cfg.nostr_relays.size(); ++i) {
        relays.push(Json::make_string(cfg.nostr_relays[i]));
    }
    obj.set("nostr_relays", relays);
    obj.set("stun_server", Json::make_string(cfg.stun_server));
    obj.set("discovery_backend", Json::make_string(cfg.discovery_backend));

    std::ofstream fh(target.c_str(), std::ios::binary | std::ios::trunc);
    if (!fh) return false;
    std::string text = obj.dump_pretty() + "\n";
    fh.write(text.data(), static_cast<std::streamsize>(text.size()));
    return fh.good();
}

}  // namespace r2p
