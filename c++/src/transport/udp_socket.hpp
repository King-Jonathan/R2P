#ifndef R2P_TRANSPORT_UDP_SOCKET_HPP
#define R2P_TRANSPORT_UDP_SOCKET_HPP

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "discovery/presence.hpp"

namespace r2p {

static const uint16_t kPortScanSpan = 64;
static const uint16_t kLanBroadcastLookahead = 3;

class UdpTransport {
public:
    typedef std::function<void(const uint8_t*, size_t, const Endpoint&)> RecvHandler;
    typedef std::function<void(const std::string&)> ErrorHandler;

    explicit UdpTransport(uint16_t preferred_port, RecvHandler on_packet = RecvHandler());
    ~UdpTransport();

    UdpTransport(const UdpTransport&) = delete;
    UdpTransport& operator=(const UdpTransport&) = delete;

    uint16_t port() const { return port_.load(); }
    uint16_t preferred_port() const { return preferred_port_.load(); }

    void set_handler(RecvHandler handler);
    void set_error_handler(ErrorHandler handler);

    bool start();
    void stop();
    bool rebind(uint16_t preferred_port);

    void enqueue_send(const std::vector<uint8_t>& data, const Endpoint& addr, double delay_s = 0.0);
    void discard_sends(uint8_t protocol);
    std::vector<uint16_t> broadcast_ports() const;
    bool stun_query(const std::string& server, Endpoint& mapped_out, double timeout_s = 2.0);

private:
    struct QueuedSend {
        std::chrono::steady_clock::time_point due;
        uint64_t seq;
        std::vector<uint8_t> data;
        Endpoint addr;

        bool operator>(const QueuedSend& o) const {
            if (due != o.due) return due > o.due;
            return seq > o.seq;
        }
    };

    void recv_loop();
    void send_loop();
    void report_error(const std::string& msg);

    std::atomic<uint16_t> preferred_port_;
    std::atomic<uint16_t> port_;
    RecvHandler on_packet_;
    ErrorHandler on_error_;
    double last_error_at_;

    mutable std::mutex mu_;
    std::condition_variable send_cv_;
    int sock_;
    std::atomic<bool> stop_flag_;
    std::thread recv_thread_;
    std::thread send_thread_;
    std::priority_queue<QueuedSend, std::vector<QueuedSend>, std::greater<QueuedSend> > send_q_;
    uint64_t send_seq_;

    // Same-socket STUN state.
    std::mutex stun_mu_;
    std::condition_variable stun_cv_;
    bool stun_waiting_;
    bool stun_ready_;
    std::array<uint8_t, 12> stun_tx_;
    Endpoint stun_result_;
};

}  // namespace r2p

#endif
