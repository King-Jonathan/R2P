#include "transport/udp_socket.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <set>
#include <sys/socket.h>
#include <unistd.h>

#include "discovery/stun_client.hpp"

namespace r2p {

namespace {

bool bind_free_port(uint16_t preferred, int& fd_out, uint16_t& bound_out) {
    uint16_t base = (preferred == 0) ? 1 : preferred;
    for (uint32_t offset = 0; offset <= kPortScanSpan; ++offset) {
        uint32_t p = static_cast<uint32_t>(base) + offset;
        if (p > 65535) break;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) continue;
        int bcast = 1;
        setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));
        struct sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(static_cast<uint16_t>(p));
        if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0) {
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            fd_out = fd;
            bound_out = static_cast<uint16_t>(p);
            return true;
        }
        close(fd);
    }
    return false;
}

void send_datagram(int fd, const std::vector<uint8_t>& data, const Endpoint& ep) {
    if (fd < 0 || data.empty()) return;
    struct sockaddr_in dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(ep.port);
    if (inet_pton(AF_INET, ep.host.c_str(), &dst.sin_addr) != 1) return;
    sendto(fd, data.data(), data.size(), 0,
           reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));
}

}  // namespace

UdpTransport::UdpTransport(uint16_t preferred_port, RecvHandler on_packet)
    : preferred_port_(preferred_port),
      port_(preferred_port),
      on_packet_(on_packet),
      last_error_at_(0.0),
      sock_(-1),
      stop_flag_(true),
      send_seq_(0),
      stun_waiting_(false),
      stun_ready_(false),
      stun_tx_() {}

UdpTransport::~UdpTransport() {
    stop();
}

void UdpTransport::set_handler(RecvHandler handler) {
    std::lock_guard<std::mutex> lock(mu_);
    on_packet_ = handler;
}

void UdpTransport::set_error_handler(ErrorHandler handler) {
    std::lock_guard<std::mutex> lock(mu_);
    on_error_ = handler;
}

bool UdpTransport::start() {
    std::lock_guard<std::mutex> lock(mu_);
    if (sock_ >= 0) return true;
    int fd = -1;
    uint16_t bound = 0;
    if (!bind_free_port(preferred_port_.load(), fd, bound)) return false;
    sock_ = fd;
    port_.store(bound);
    stop_flag_.store(false);
    recv_thread_ = std::thread(&UdpTransport::recv_loop, this);
    send_thread_ = std::thread(&UdpTransport::send_loop, this);
    return true;
}

void UdpTransport::stop() {
    stop_flag_.store(true);
    int fd = -1;
    {
        std::lock_guard<std::mutex> lock(mu_);
        fd = sock_;
        sock_ = -1;
        while (!send_q_.empty()) send_q_.pop();
    }
    send_cv_.notify_all();
    {
        std::lock_guard<std::mutex> sl(stun_mu_);
        stun_waiting_ = false;
    }
    stun_cv_.notify_all();
    if (fd >= 0) {
        shutdown(fd, SHUT_RDWR);
    }
    if (send_thread_.joinable()) send_thread_.join();
    if (recv_thread_.joinable()) recv_thread_.join();
    if (fd >= 0) {
        close(fd);
    }
}

bool UdpTransport::rebind(uint16_t preferred) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (sock_ >= 0 && port_.load() == preferred) {
            preferred_port_.store(preferred);
            return true;
        }
    }
    int new_fd = -1;
    uint16_t new_bound = 0;
    if (!bind_free_port(preferred, new_fd, new_bound)) {
        return false;
    }
    stop();
    {
        std::lock_guard<std::mutex> lock(mu_);
        sock_ = new_fd;
        preferred_port_.store(preferred);
        port_.store(new_bound);
        stop_flag_.store(false);
        recv_thread_ = std::thread(&UdpTransport::recv_loop, this);
        send_thread_ = std::thread(&UdpTransport::send_loop, this);
    }
    return true;
}

void UdpTransport::enqueue_send(const std::vector<uint8_t>& data, const Endpoint& addr,
                                double delay_s) {
    auto due = std::chrono::steady_clock::now() +
               std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                   std::chrono::duration<double>(delay_s > 0.0 ? delay_s : 0.0));
    {
        std::lock_guard<std::mutex> lock(mu_);
        QueuedSend item;
        item.due = due;
        item.seq = send_seq_++;
        item.data = data;
        item.addr = addr;
        send_q_.push(item);
    }
    send_cv_.notify_one();
}

void UdpTransport::discard_sends(uint8_t protocol) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        std::priority_queue<QueuedSend, std::vector<QueuedSend>, std::greater<QueuedSend> > kept;
        while (!send_q_.empty()) {
            QueuedSend item = send_q_.top();
            send_q_.pop();
            if (item.data.empty() || item.data[0] != protocol) {
                kept.push(item);
            }
        }
        send_q_.swap(kept);
    }
    send_cv_.notify_one();
}

std::vector<uint16_t> UdpTransport::broadcast_ports() const {
    std::set<uint16_t> ports;
    ports.insert(port_.load());
    uint16_t base = preferred_port_.load();
    for (uint32_t i = 0; i <= kLanBroadcastLookahead; ++i) {
        uint32_t p = static_cast<uint32_t>(base) + i;
        if (p >= 1 && p <= 65535) ports.insert(static_cast<uint16_t>(p));
    }
    return std::vector<uint16_t>(ports.begin(), ports.end());
}

bool UdpTransport::stun_query(const std::string& server, Endpoint& mapped_out, double timeout_s) {
    std::string host;
    uint16_t port = 19302;
    parse_host_port(server, host, port);

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return false;
    struct sockaddr_in dst;
    std::memcpy(&dst, res->ai_addr, sizeof(dst));
    dst.sin_port = htons(port);
    freeaddrinfo(res);

    std::vector<uint8_t> req;
    std::array<uint8_t, 12> tx_id;
    build_stun_binding_request(req, tx_id);

    int fd = -1;
    {
        std::lock_guard<std::mutex> lock(mu_);
        fd = sock_;
    }
    if (fd < 0) return false;

    {
        std::lock_guard<std::mutex> sl(stun_mu_);
        stun_tx_ = tx_id;
        stun_waiting_ = true;
        stun_ready_ = false;
    }

    if (sendto(fd, req.data(), req.size(), 0,
               reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst)) < 0) {
        std::lock_guard<std::mutex> sl(stun_mu_);
        stun_waiting_ = false;
        return false;
    }

    std::unique_lock<std::mutex> sl(stun_mu_);
    bool got = stun_cv_.wait_for(
        sl,
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::duration<double>(timeout_s)),
        [this]() { return stun_ready_ || !stun_waiting_; });
    bool ok = got && stun_ready_;
    if (ok) mapped_out = stun_result_;
    stun_waiting_ = false;
    return ok;
}

void UdpTransport::recv_loop() {
    uint8_t buf[2048];
    while (!stop_flag_.load()) {
        int fd = -1;
        {
            std::lock_guard<std::mutex> lock(mu_);
            fd = sock_;
        }
        if (fd < 0) break;

        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int r = poll(&pfd, 1, 50);
        if (r <= 0) continue;

        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             reinterpret_cast<struct sockaddr*>(&from), &from_len);
        if (n <= 0) continue;

        if (is_stun_response(buf, static_cast<size_t>(n))) {
            std::array<uint8_t, 12> tx;
            bool waiting = false;
            {
                std::lock_guard<std::mutex> sl(stun_mu_);
                waiting = stun_waiting_;
                tx = stun_tx_;
            }
            Endpoint mapped;
            if (waiting && parse_stun_mapped_address(buf, static_cast<size_t>(n), &tx, mapped)) {
                {
                    std::lock_guard<std::mutex> sl(stun_mu_);
                    stun_result_ = mapped;
                    stun_ready_ = true;
                }
                stun_cv_.notify_all();
            }
            continue;
        }

        char ip_buf[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &from.sin_addr, ip_buf, sizeof(ip_buf))) continue;
        Endpoint sender(ip_buf, ntohs(from.sin_port));

        RecvHandler handler;
        {
            std::lock_guard<std::mutex> lock(mu_);
            handler = on_packet_;
        }
        if (handler) {
            try {
                handler(buf, static_cast<size_t>(n), sender);
            } catch (...) {
                report_error("recv error");
            }
        }
    }
}

void UdpTransport::send_loop() {
    while (!stop_flag_.load()) {
        std::vector<std::pair<std::vector<uint8_t>, Endpoint> > due;
        int fd = -1;
        {
            std::unique_lock<std::mutex> lock(mu_);
            send_cv_.wait(lock, [this]() { return stop_flag_.load() || !send_q_.empty(); });
            if (stop_flag_.load()) break;
            auto now = std::chrono::steady_clock::now();
            auto next_due = send_q_.top().due;
            if (next_due > now) {
                send_cv_.wait_until(lock, next_due);
                continue;
            }
            fd = sock_;
            while (!send_q_.empty() && send_q_.top().due <= now) {
                due.push_back(std::make_pair(send_q_.top().data, send_q_.top().addr));
                send_q_.pop();
            }
        }
        if (fd < 0) break;
        for (size_t i = 0; i < due.size(); ++i) {
            send_datagram(fd, due[i].first, due[i].second);
        }
    }
}

void UdpTransport::report_error(const std::string& msg) {
    double now = std::chrono::duration<double>(
                     std::chrono::steady_clock::now().time_since_epoch())
                     .count();
    ErrorHandler cb;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (now - last_error_at_ < 5.0) return;
        last_error_at_ = now;
        cb = on_error_;
    }
    if (cb) cb(msg);
}

}  // namespace r2p
