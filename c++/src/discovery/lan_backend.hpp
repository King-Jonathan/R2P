#ifndef R2P_DISCOVERY_LAN_BACKEND_HPP
#define R2P_DISCOVERY_LAN_BACKEND_HPP

#include <atomic>
#include <cstdint>
#include <functional>

namespace r2p {

class LanDiscoveryBackend {
public:
    typedef std::function<void()> PublishFn;

    explicit LanDiscoveryBackend(PublishFn publish_fn, double interval_s = 30.0)
        : publish_fn_(publish_fn),
          interval_(interval_s),
          last_pub_(0.0),
          running_(false) {}

    void start() {
        running_.store(true);
        last_pub_ = 0.0;
    }

    void stop() { running_.store(false); }

    void tick(double now) {
        if (!running_.load()) return;
        if (now - last_pub_ >= interval_) {
            if (publish_fn_) publish_fn_();
            last_pub_ = now;
        }
    }

    void on_vibe_changed(uint8_t) { last_pub_ = 0.0; }

private:
    PublishFn publish_fn_;
    double interval_;
    double last_pub_;
    std::atomic<bool> running_;
};

}  // namespace r2p

#endif
