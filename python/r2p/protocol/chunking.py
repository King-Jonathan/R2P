"""Callsign prepend, body chunk split and reassembly."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from r2p.protocol.packet import MAX_CHUNK_ID

# Header 26 + body; keep body <= 200 before encryption (216 with 16-byte AEAD tag).
MAX_CHUNK_BODY = 200
MAX_MESSAGE_BYTES = 2 * 1024 * 1024
MAX_VALID_CHUNK_ID = MAX_MESSAGE_BYTES // MAX_CHUNK_BODY
SEPARATOR = " ¦ "


def build_message_body(callsign: str, message: str) -> str:
    cs = (callsign or "")[:16]
    return f"{cs}{SEPARATOR}{message}"


def chunk_body(encoded: bytes, max_chunk: int = MAX_CHUNK_BODY) -> list[bytes]:
    """
    Split body into chunks. The final chunk is always shorter than max_chunk
    (empty if the payload length is an exact multiple of max_chunk).
    """
    if max_chunk < 1:
        raise ValueError("max_chunk must be >= 1")
    if len(encoded) > MAX_MESSAGE_BYTES or len(encoded) // max_chunk > MAX_CHUNK_ID:
        raise ValueError("message is too large")
    return [encoded[i : i + max_chunk] for i in range(0, len(encoded) + 1, max_chunk)]


def is_final_chunk(body_len: int, max_chunk: int = MAX_CHUNK_BODY) -> bool:
    """True when body_len is strictly shorter than max_chunk (final chunk)."""
    return body_len < max_chunk


@dataclass
class Reassembly:
    """Collect decrypted byte chunks by message_id."""

    started: float
    chunks: dict[int, bytes] = field(default_factory=dict)
    final_id: int | None = None
    size: int = 0

    def add(self, chunk_id: int, body: bytes, max_chunk: int = MAX_CHUNK_BODY) -> bytes | None:
        if chunk_id in self.chunks:
            return None
        if self.final_id is not None and chunk_id > self.final_id:
            raise ValueError("chunk follows the final chunk")
        if self.size + len(body) > MAX_MESSAGE_BYTES:
            raise ValueError("message is too large")
        if is_final_chunk(len(body), max_chunk):
            if self.final_id is not None or any(cid > chunk_id for cid in self.chunks):
                raise ValueError("conflicting final chunk")
            self.final_id = chunk_id
        self.chunks[chunk_id] = body
        self.size += len(body)
        if self.final_id is not None and len(self.chunks) == self.final_id + 1:
            return b"".join(self.chunks[i] for i in range(self.final_id + 1))
        return None


MAX_PENDING = 16
PENDING_TTL = 60.0


class MessageAssembler:
    def __init__(self, max_chunk: int = MAX_CHUNK_BODY) -> None:
        self._max_chunk = max_chunk
        self._pending: dict[bytes, Reassembly] = {}

    def feed(self, message_id: bytes, chunk_id: int, body: bytes, now: float | None = None) -> bytes | None:
        t = time.time() if now is None else now
        if not 0 <= chunk_id <= MAX_CHUNK_ID or len(body) > self._max_chunk:
            return None
        if chunk_id * self._max_chunk + len(body) > MAX_MESSAGE_BYTES:
            return None
        self.purge(t)
        state = self._pending.get(message_id)
        if state is None:
            if len(self._pending) >= MAX_PENDING:
                oldest = min(self._pending, key=lambda mid: self._pending[mid].started)
                self.drop(oldest)
            state = Reassembly(started=t)
            self._pending[message_id] = state
        try:
            result = state.add(chunk_id, body, self._max_chunk)
        except ValueError:
            self.drop(message_id)
            return None
        if result is not None:
            self.drop(message_id)
        return result

    def purge(self, now: float | None = None) -> None:
        t = time.time() if now is None else now
        dead = [mid for mid, state in self._pending.items() if t - state.started >= PENDING_TTL]
        for mid in dead:
            self.drop(mid)

    def pending_count(self) -> int:
        return len(self._pending)

    def drop(self, message_id: bytes) -> None:
        self._pending.pop(message_id, None)
