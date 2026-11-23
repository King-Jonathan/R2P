#ifndef R2P_DISCOVERY_WS_CLIENT_HPP
#define R2P_DISCOVERY_WS_CLIENT_HPP

#include <atomic>
#include <cstdint>
#include <mutex>
#include <openssl/ssl.h>
#include <string>

namespace r2p {

// Minimal RFC 6455 client over TCP + OpenSSL TLS (wss:// and ws://).
class WsClient {
public:
    WsClient();
    ~WsClient();

    WsClient(const WsClient&) = delete;
    WsClient& operator=(const WsClient&) = delete;

    bool connect(const std::string& url, int timeout_ms = 8000);
    bool send_text(const std::string& msg);
    // Returns 1 on message, 0 on timeout, -1 on close/error.
    int recv_text(std::string& out, int timeout_ms = 1000);
    // Safe to call from another thread to wake blocked I/O without freeing SSL/fd.
    void shutdown_io();
    // Free SSL and close fd; call only from the owning thread or destructor.
    void close();
    bool is_open() const { return open_.load(); }

private:
    bool raw_write_all_locked(const uint8_t* data, size_t len);
    int raw_read_exact(uint8_t* buf, size_t len, int timeout_ms);
    bool send_frame(uint8_t opcode, const uint8_t* data, size_t len);

    int fd_;
    SSL_CTX* ssl_ctx_;
    SSL* ssl_;
    std::atomic<bool> open_;
    std::mutex fd_mu_;
    std::mutex io_mu_;
};

}  // namespace r2p

#endif
