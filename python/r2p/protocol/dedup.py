"""Drop duplicate (message_id, chunk_id) pairs for 10 minutes using bounded bitsets."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict

from r2p.protocol.chunking import MAX_VALID_CHUNK_ID


class DedupCache:
    def __init__(
        self,
        ttl_seconds: float = 600.0,
        max_ids: int = 4096,
        max_chunk_id: int = MAX_VALID_CHUNK_ID,
    ) -> None:
        self._ttl = ttl_seconds
        self._max_ids = max_ids
        self._max_chunk_id = max_chunk_id
        self._lock = threading.Lock()
        # insertion order = oldest first; value = (first_seen, bitset bytearray)
        self._seen: OrderedDict[bytes, tuple[float, bytearray]] = OrderedDict()

    def is_duplicate(self, message_id: bytes, chunk_id: int, now: float | None = None) -> bool:
        """Return True if this pair was already accepted (or out of range). Else record."""
        if not (0 <= chunk_id <= self._max_chunk_id):
            return True
        t = time.time() if now is None else now
        byte_idx = chunk_id >> 3
        mask = 1 << (chunk_id & 7)
        with self._lock:
            # Check this id here; the core timer purges other expired ids.
            entry = self._seen.get(message_id)
            if entry is not None and t - entry[0] >= self._ttl:
                del self._seen[message_id]
                entry = None
            if entry is None:
                while len(self._seen) >= self._max_ids:
                    self._seen.popitem(last=False)
                bits = bytearray(byte_idx + 1)
                bits[byte_idx] = mask
                self._seen[message_id] = (t, bits)
                return False
            _first_seen, bits = entry
            if byte_idx < len(bits):
                if bits[byte_idx] & mask:
                    return True
                bits[byte_idx] |= mask
                return False
            bits.extend(bytes(byte_idx + 1 - len(bits)))
            bits[byte_idx] = mask
            return False

    def purge(self, now: float | None = None) -> None:
        t = time.time() if now is None else now
        with self._lock:
            expired = [mid for mid, (first, _) in self._seen.items() if t - first >= self._ttl]
            for mid in expired:
                del self._seen[mid]

    def size(self) -> int:
        with self._lock:
            return len(self._seen)
