"""Known peer endpoints."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

MAX_PEERS = 64


@dataclass
class Peer:
    host: str
    port: int
    last_seen: float


class PeerList:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._peers: dict[tuple[str, int], Peer] = {}
        self._self: set[tuple[str, int]] = set()

    def replace_self(self, endpoints: set[tuple[str, int]]) -> None:
        """Replace the local endpoint set (do not accumulate stale ports)."""
        with self._lock:
            self._self = {(h, int(p)) for h, p in endpoints}

    def is_self(self, host: str, port: int) -> bool:
        with self._lock:
            return (host, int(port)) in self._self

    def add(self, host: str, port: int, now: float | None = None) -> bool:
        """Add or refresh peer. Return True if newly added."""
        t = time.time() if now is None else now
        key = (host, int(port))
        with self._lock:
            if key in self._self:
                return False
            existed = key in self._peers
            self._peers[key] = Peer(host=host, port=int(port), last_seen=t)
            while len(self._peers) > MAX_PEERS:
                oldest = min(self._peers.values(), key=lambda p: p.last_seen)
                del self._peers[(oldest.host, oldest.port)]
            return not existed

    def clear(self) -> None:
        with self._lock:
            self._peers.clear()

    def all(self) -> list[tuple[str, int]]:
        with self._lock:
            return [(p.host, p.port) for p in self._peers.values()]

    def purge_older_than(self, max_age: float, now: float | None = None) -> None:
        t = time.time() if now is None else now
        with self._lock:
            dead = [k for k, p in self._peers.items() if t - p.last_seen > max_age]
            for k in dead:
                del self._peers[k]
