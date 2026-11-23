#include "discovery/ws_client.hpp"

#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "util/base64.hpp"

namespace r2p {

namespace {

bool parse_ws_url(const std::string& url, bool& use_tls, std::string& host,
                  uint16_t& port, std::string& path) {
    size_t pos = 0;
    if (url.compare(0, 6, "wss://") == 0) {
        use_tls = true;
        port = 443;
        pos = 6;
    } else if (url.compare(0, 5, "ws://") == 0) {
        use_tls = false;
        port = 80;
        pos = 5;
    } else {
        return false;
    }
    size_t slash = url.find('/', pos);
    std::string hostport = (slash == std::string::npos) ? url.substr(pos) : url.substr(pos, slash - pos);
    path = (slash == std::string::npos) ? "/" : url.substr(slash);
    size_t colon = hostport.rfind(':');
    if (colon != std::string::npos) {
        host = hostport.substr(0, colon);
        long p = std::strtol(hostport.substr(colon + 1).c_str(), nullptr, 10);
        if (p < 1 || p > 65535) return false;
        port = static_cast<uint16_t>(p);
    } else {
        host = hostport;
    }
    return !host.empty();
}

int connect_tcp(const std::string& host, uint16_t port, int timeout_ms) {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    std::snprintf(port_str, sizeof(port_str), "%u", static_cast<unsigned>(port));
    struct addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port_str, &hints, &res) != 0 || !res) return -1;

    int fd = -1;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int rc = ::connect(fd, p->ai_addr, p->ai_addrlen);
        if (rc == 0) {
            if (flags >= 0) fcntl(fd, F_SETFL, flags);
            break;
        }
        if (errno == EINPROGRESS) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            if (poll(&pfd, 1, timeout_ms) > 0) {
                int err = 0;
                socklen_t elen = sizeof(err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 && err == 0) {
                    if (flags >= 0) fcntl(fd, F_SETFL, flags);
                    break;
                }
            }
        }
        ::close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) {
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    return fd;
}

}  // namespace

WsClient::WsClient() : fd_(-1), ssl_ctx_(nullptr), ssl_(nullptr), open_(false) {}

WsClient::~WsClient() {
    close();
}

bool WsClient::connect(const std::string& url, int timeout_ms) {
    close();
    bool use_tls = true;
    std::string host;
    uint16_t port = 443;
    std::string path;
    if (!parse_ws_url(url, use_tls, host, port, path)) return false;

    fd_ = connect_tcp(host, port, timeout_ms);
    if (fd_ < 0) return false;

    if (use_tls) {
        ssl_ctx_ = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx_ || SSL_CTX_set_default_verify_paths(ssl_ctx_) != 1) {
            close();
            return false;
        }
        SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, nullptr);
        ssl_ = SSL_new(ssl_ctx_);
        if (!ssl_) {
            close();
            return false;
        }
        SSL_set_tlsext_host_name(ssl_, host.c_str());
        SSL_set1_host(ssl_, host.c_str());
        SSL_set_fd(ssl_, fd_);
        if (SSL_connect(ssl_) != 1 || SSL_get_verify_result(ssl_) != X509_V_OK) {
            close();
            return false;
        }
    }

    uint8_t key_bytes[16];
    RAND_bytes(key_bytes, sizeof(key_bytes));
    std::string ws_key = base64_encode(key_bytes, sizeof(key_bytes));
    std::string host_hdr = host;
    if ((use_tls && port != 443) || (!use_tls && port != 80)) {
        host_hdr += ":" + std::to_string(port);
    }
    std::string req = "GET " + path + " HTTP/1.1\r\n"
                      "Host: " + host_hdr + "\r\n"
                      "Upgrade: websocket\r\n"
                      "Connection: Upgrade\r\n"
                      "Sec-WebSocket-Key: " + ws_key + "\r\n"
                      "Sec-WebSocket-Version: 13\r\n\r\n";
    open_.store(true);
    {
        std::lock_guard<std::mutex> lock(io_mu_);
        if (!raw_write_all_locked(reinterpret_cast<const uint8_t*>(req.data()), req.size())) {
            open_.store(false);
            close();
            return false;
        }
    }

    // Read HTTP upgrade response headers up to \r\n\r\n.
    std::string headers;
    char ch = 0;
    while (headers.size() < 8192) {
        int r = raw_read_exact(reinterpret_cast<uint8_t*>(&ch), 1, timeout_ms);
        if (r != 1) {
            close();
            return false;
        }
        headers.push_back(ch);
        if (headers.size() >= 4 && headers.compare(headers.size() - 4, 4, "\r\n\r\n") == 0) {
            break;
        }
    }
    size_t eol = headers.find("\r\n");
    std::string status_line = (eol == std::string::npos) ? headers : headers.substr(0, eol);
    if (status_line.compare(0, 12, "HTTP/1.1 101") != 0 &&
        status_line.compare(0, 12, "HTTP/1.0 101") != 0) {
        close();
        return false;
    }
    return true;
}

bool WsClient::raw_write_all_locked(const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = 0;
        if (ssl_) {
            n = SSL_write(ssl_, data + sent, static_cast<int>(len - sent));
        } else if (fd_ >= 0) {
            n = static_cast<int>(::send(fd_, data + sent, len - sent, MSG_NOSIGNAL));
        }
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

int WsClient::raw_read_exact(uint8_t* buf, size_t len, int timeout_ms) {
    size_t got = 0;
    int remaining = timeout_ms;
    while (got < len) {
        if (!open_.load()) return -1;
        {
            std::lock_guard<std::mutex> lock(io_mu_);
            if (ssl_ && SSL_pending(ssl_) > 0) {
                int n = SSL_read(ssl_, buf + got, static_cast<int>(len - got));
                if (n <= 0) return -1;
                got += static_cast<size_t>(n);
                continue;
            }
        }
        int fd = -1;
        {
            std::lock_guard<std::mutex> fl(fd_mu_);
            fd = fd_;
        }
        if (fd < 0) return -1;
        int step = (remaining > 100) ? 100 : remaining;
        if (step < 1) step = 1;
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, step);
        if (pr == 0) {
            remaining -= step;
            if (remaining <= 0) return (got == 0) ? 0 : -1;
            continue;
        }
        if (pr < 0) return -1;
        if (!open_.load()) return -1;
        int n = 0;
        {
            std::lock_guard<std::mutex> lock(io_mu_);
            if (ssl_) {
                n = SSL_read(ssl_, buf + got, static_cast<int>(len - got));
            } else if (fd_ >= 0) {
                n = static_cast<int>(::recv(fd_, buf + got, len - got, 0));
            }
        }
        if (n <= 0) return -1;
        got += static_cast<size_t>(n);
    }
    return 1;
}

bool WsClient::send_frame(uint8_t opcode, const uint8_t* data, size_t len) {
    std::lock_guard<std::mutex> lock(io_mu_);
    if (!open_.load() && opcode != 0x8) return false;
    std::vector<uint8_t> frame;
    frame.reserve(14 + len);
    frame.push_back(static_cast<uint8_t>(0x80 | (opcode & 0x0F)));
    if (len < 126) {
        frame.push_back(static_cast<uint8_t>(0x80 | len));
    } else if (len <= 65535) {
        frame.push_back(static_cast<uint8_t>(0x80 | 126));
        frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(len & 0xFF));
    } else {
        frame.push_back(static_cast<uint8_t>(0x80 | 127));
        uint64_t ulen = static_cast<uint64_t>(len);
        for (int i = 7; i >= 0; --i) {
            frame.push_back(static_cast<uint8_t>((ulen >> (i * 8)) & 0xFF));
        }
    }
    uint8_t mask[4];
    RAND_bytes(mask, 4);
    frame.insert(frame.end(), mask, mask + 4);
    for (size_t i = 0; i < len; ++i) {
        frame.push_back(static_cast<uint8_t>(data[i] ^ mask[i & 3]));
    }
    return raw_write_all_locked(frame.data(), frame.size());
}

bool WsClient::send_text(const std::string& msg) {
    return send_frame(0x1, reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
}

int WsClient::recv_text(std::string& out, int timeout_ms) {
    out.clear();
    std::string accum;
    bool in_frag = false;
    while (open_.load()) {
        uint8_t hdr[2];
        int r = raw_read_exact(hdr, 2, timeout_ms);
        if (r <= 0) return r;
        bool fin = (hdr[0] & 0x80) != 0;
        uint8_t op = hdr[0] & 0x0F;
        bool masked = (hdr[1] & 0x80) != 0;
        uint64_t plen = hdr[1] & 0x7F;
        if (plen == 126) {
            uint8_t ext[2];
            if (raw_read_exact(ext, 2, timeout_ms) != 1) return -1;
            plen = (static_cast<uint64_t>(ext[0]) << 8) | ext[1];
        } else if (plen == 127) {
            uint8_t ext[8];
            if (raw_read_exact(ext, 8, timeout_ms) != 1) return -1;
            plen = 0;
            for (int i = 0; i < 8; ++i) plen = (plen << 8) | ext[i];
        }
        // Bound relay frame size to 256 KiB.
        if (plen > 262144) return -1;
        uint8_t mask[4] = {0, 0, 0, 0};
        if (masked && raw_read_exact(mask, 4, timeout_ms) != 1) return -1;
        std::vector<uint8_t> payload(static_cast<size_t>(plen));
        if (plen > 0 && raw_read_exact(payload.data(), payload.size(), timeout_ms) != 1) {
            return -1;
        }
        if (masked) {
            for (size_t i = 0; i < payload.size(); ++i) payload[i] ^= mask[i & 3];
        }
        if (op == 0x8) {  // close
            open_.store(false);
            return -1;
        }
        if (op == 0x9) {  // ping -> pong
            send_frame(0xA, payload.data(), payload.size());
            continue;
        }
        if (op == 0xA) continue;  // pong
        if (op == 0x1 || op == 0x2 || (op == 0x0 && in_frag)) {
            if (accum.size() + payload.size() > 262144) return -1;
            accum.append(reinterpret_cast<const char*>(payload.data()), payload.size());
            in_frag = !fin;
            if (fin) {
                out.swap(accum);
                return 1;
            }
        }
    }
    return -1;
}

void WsClient::shutdown_io() {
    open_.store(false);
    std::lock_guard<std::mutex> fl(fd_mu_);
    if (fd_ >= 0) {
        ::shutdown(fd_, SHUT_RDWR);
    }
}

void WsClient::close() {
    open_.store(false);
    std::lock_guard<std::mutex> lock(io_mu_);
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (ssl_ctx_) {
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
    }
    std::lock_guard<std::mutex> fl(fd_mu_);
    if (fd_ >= 0) {
        ::shutdown(fd_, SHUT_RDWR);
        ::close(fd_);
        fd_ = -1;
    }
}

}  // namespace r2p
