"""UDP bind, send, receive, optional broadcast, same-socket STUN."""

from __future__ import annotations

import heapq
import select
import socket
import threading
import time
from collections.abc import Callable

from r2p.discovery.stun_client import (
    _parse_host_port,
    build_binding_request,
    is_stun_response,
    parse_mapped_address,
)

RecvHandler = Callable[[bytes, tuple[str, int]], None]
ErrorHandler = Callable[[str], None]

PORT_SCAN_SPAN = 64
LAN_BROADCAST_LOOKAHEAD = 3


class UdpTransport:
    def __init__(self, port: int, on_packet: RecvHandler | None = None) -> None:
        self._preferred_port = int(port)
        self._port = int(port)
        self._on_packet = on_packet
        self._on_error: ErrorHandler | None = None
        self._last_error_at = 0.0
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._send_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._send_cond = threading.Condition(self._lock)
        self._send_q: list[tuple[float, int, bytes, tuple[str, int]]] = []
        self._send_seq = 0
        self._stun_tx: bytes | None = None
        self._stun_result: tuple[str, int] | None = None
        self._stun_event = threading.Event()

    @property
    def port(self) -> int:
        return self._port

    @property
    def preferred_port(self) -> int:
        return self._preferred_port

    def set_handler(self, handler: RecvHandler | None) -> None:
        self._on_packet = handler

    def set_error_handler(self, handler: ErrorHandler | None) -> None:
        self._on_error = handler

    def start(self) -> None:
        with self._lock:
            if self._sock is not None:
                return
            sock, bound = _bind_free_port(self._preferred_port)
            self._port = bound
            self._sock = sock
            self._stop.clear()
            self._thread = threading.Thread(target=self._recv_loop, name="udp-recv", daemon=True)
            self._send_thread = threading.Thread(target=self._send_loop, name="udp-send", daemon=True)
            self._thread.start()
            self._send_thread.start()

    def stop(self) -> None:
        self._stop.set()
        with self._send_cond:
            sock = self._sock
            self._sock = None
            self._send_q.clear()
            self._send_cond.notify_all()
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self._send_thread is not None:
            self._send_thread.join(timeout=1.0)
            self._send_thread = None
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None

    def rebind(self, port: int) -> None:
        """Rebind to preferred port (or next free port); restore previous port on failure."""
        old_pref = self._preferred_port
        old_port = self._port
        self.stop()
        self._preferred_port = int(port)
        self._port = int(port)
        try:
            self.start()
        except OSError:
            self._preferred_port = old_pref
            self._port = old_port
            try:
                self.start()
            except OSError:
                pass
            raise

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        self.enqueue_send(data, addr, delay_s=0.0)

    def enqueue_send(self, data: bytes, addr: tuple[str, int], delay_s: float = 0.0) -> None:
        due = time.monotonic() + max(0.0, delay_s)
        with self._send_cond:
            heapq.heappush(self._send_q, (due, self._send_seq, data, addr))
            self._send_seq += 1
            self._send_cond.notify()

    def broadcast_ports(self) -> list[int]:
        ports = {self._port}
        base = self._preferred_port
        for i in range(LAN_BROADCAST_LOOKAHEAD + 1):
            p = base + i
            if 1 <= p <= 65535:
                ports.add(p)
        return sorted(ports)

    def discard_sends(self, protocol: int) -> None:
        """Remove queued packets for a chat mode that the user has left."""
        with self._send_cond:
            self._send_q = [item for item in self._send_q if item[2][0] != protocol]
            heapq.heapify(self._send_q)
            self._send_cond.notify()

    def stun_query(self, server: str, timeout: float = 2.0) -> tuple[str, int] | None:
        """Send Binding Request on the listen socket; wait for XOR-MAPPED on recv thread."""
        host, port = _parse_host_port(server)
        packet, tx_id = build_binding_request()
        self._stun_event.clear()
        with self._lock:
            self._stun_tx = tx_id
            self._stun_result = None
            sock = self._sock
        if sock is None:
            return None
        try:
            sock.sendto(packet, (host, port))
        except OSError:
            return None
        if not self._stun_event.wait(timeout):
            with self._lock:
                self._stun_tx = None
            return None
        with self._lock:
            self._stun_tx = None
            return self._stun_result

    def _recv_loop(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                sock = self._sock
            if sock is None:
                break
            try:
                ready, _, _ = select.select([sock], [], [], 0.05)
            except (OSError, ValueError):
                break
            if not ready:
                continue
            try:
                data, addr = sock.recvfrom(2048)
            except OSError:
                continue
            if not data:
                continue
            if is_stun_response(data):
                with self._lock:
                    tx = self._stun_tx
                mapped = parse_mapped_address(data, tx)
                if mapped is not None:
                    with self._lock:
                        self._stun_result = mapped
                    self._stun_event.set()
                continue
            handler = self._on_packet
            if handler is not None:
                try:
                    handler(data, (addr[0], int(addr[1])))
                except Exception:
                    self._report_error("recv error")

    def _send_loop(self) -> None:
        while not self._stop.is_set():
            due: list[tuple[bytes, tuple[str, int]]] = []
            with self._send_cond:
                while not self._stop.is_set() and not self._send_q:
                    self._send_cond.wait()
                if self._stop.is_set():
                    break
                now = time.monotonic()
                wait = self._send_q[0][0] - now
                if wait > 0:
                    self._send_cond.wait(timeout=wait)
                    continue
                sock = self._sock
                while self._send_q and self._send_q[0][0] <= now:
                    _t, _seq, data, addr = heapq.heappop(self._send_q)
                    due.append((data, addr))
            if sock is None:
                break
            for data, addr in due:
                try:
                    sock.sendto(data, addr)
                except OSError:
                    pass

    def _report_error(self, msg: str) -> None:
        now = time.time()
        if now - self._last_error_at < 5.0:
            return
        self._last_error_at = now
        cb = self._on_error
        if cb is not None:
            cb(msg)


def _bind_free_port(preferred: int) -> tuple[socket.socket, int]:
    """
    Bind UDP on preferred port. If that port is in use, try the next free ports.

    Does not set SO_REUSEADDR so two clients on one host do not share one port.
    """
    preferred = max(1, min(65535, int(preferred)))
    last_err: OSError | None = None
    for offset in range(PORT_SCAN_SPAN + 1):
        port = preferred + offset
        if port > 65535:
            break
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass
        try:
            sock.bind(("0.0.0.0", port))
            sock.setblocking(False)
            return sock, port
        except OSError as exc:
            last_err = exc
            try:
                sock.close()
            except OSError:
                pass
    raise OSError(
        f"no free UDP port in {preferred}..{min(65535, preferred + PORT_SCAN_SPAN)}"
    ) from last_err
