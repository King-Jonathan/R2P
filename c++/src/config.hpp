#ifndef R2P_CONFIG_HPP
#define R2P_CONFIG_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace r2p {

struct Config {
    std::string default_callsign;
    std::string frequency;
    std::string channel_key;
    uint16_t udp_port;
    int visible_lines;
    std::string encoding;
    std::string message_mode;       // "pixel" | "spectrogram"
    std::vector<std::string> nostr_relays;
    std::string stun_server;
    std::string discovery_backend;  // "nostr" | "lan" | "both"
    std::string encodings_path;
    std::string config_path;

    Config();
};

bool load_config(const std::string& path, Config& out);
bool save_config(const Config& cfg, const std::string& path_override = "");

}  // namespace r2p

#endif
