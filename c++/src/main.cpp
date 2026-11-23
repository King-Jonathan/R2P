#include <iostream>
#include <string>
#include <unistd.h>

#include "config.hpp"
#include "ui/app.hpp"

namespace {

std::string parent_dir(const std::string& path) {
    size_t slash = path.find_last_of("/\\");
    return (slash == std::string::npos) ? "." : path.substr(0, slash);
}

}  // namespace

int main(int argc, char** argv) {
    std::string config_path = (argc > 1 && argv[1] && argv[1][0] != '\0') ? argv[1] : "config.json";
    r2p::Config cfg;
    if (!r2p::load_config(config_path, cfg)) {
        std::cerr << "Failed to load config: " << config_path << "\n";
        return 1;
    }
    if (access(cfg.encodings_path.c_str(), R_OK) != 0) {
        std::string candidate = parent_dir(config_path) + "/encodings.json";
        if (access(candidate.c_str(), R_OK) == 0) {
            cfg.encodings_path = candidate;
        }
    }
    r2p::UiApp app(cfg);
    return app.run();
}
