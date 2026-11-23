"""Vibe key derivation: 5-minute rotating keys from channel + frequency."""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from r2p.crypto.cipher import expand_body_key, expand_presence_key, nostr_filter_tag
from r2p.protocol.packet import MESSAGE_PROTOCOLS

SLOT_SECONDS = 300


def normalize_16(value: str | bytes) -> bytes:
    """Map a string or bytes value to exactly 16 bytes."""
    if isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raw = value
    if len(raw) == 16:
        return raw
    if len(raw) < 16:
        return raw + b"\x00" * (16 - len(raw))
    return hashlib.sha256(raw).digest()[:16]


def room_id_16(frequency: str | bytes) -> bytes:
    """
    Public UDP header room filter: SHA-256(normalize_16(frequency))[:16].
    Not reversible to the dial string; used only for fast drop before decrypt.
    """
    return hashlib.sha256(normalize_16(frequency)).digest()[:16]


def slot_for_time(unix_time: float | int | None = None) -> int:
    t = int(time.time() if unix_time is None else unix_time)
    return (t // SLOT_SECONDS) * SLOT_SECONDS


def vibe_key_for_slot(channel_key: str | bytes, frequency: str | bytes, slot: int) -> bytes:
    """
    Derive the 16-byte vibe key for one 5-minute slot via RFC 5869 HKDF-SHA256.

    salt = slot (8-byte big-endian)
    info = b"r2p-vibe-v2" || normalize_16(frequency)
    vibe_key = HKDF-SHA256(ikm=normalize_16(channel_key), salt=salt, info=info, length=16)
    """
    ck = normalize_16(channel_key)
    freq = normalize_16(frequency)
    salt = int(slot).to_bytes(8, "big")
    return HKDF(
        algorithm=SHA256(),
        length=16,
        salt=salt,
        info=b"r2p-vibe-v2" + freq,
    ).derive(ck)


@dataclass(frozen=True)
class VibeSnapshot:
    slot: int
    last: bytes
    current: bytes
    next: bytes
    body_last: bytes
    body_current: bytes
    body_next: bytes
    presence_last: bytes
    presence_current: bytes
    presence_next: bytes
    tags_by_protocol: dict[int, tuple[str, str, str]]

    def candidate_body_keys(self) -> tuple[bytes, bytes, bytes]:
        """Try current, then last, then next (minimize time skew issues)."""
        return (self.body_current, self.body_last, self.body_next)

    def candidate_presence_keys(self) -> tuple[bytes, bytes, bytes]:
        return (self.presence_current, self.presence_last, self.presence_next)

    def nostr_tags(self, protocol: int) -> tuple[str, str, str]:
        return self.tags_by_protocol[protocol]


def _build_snapshot(channel_key: str, frequency: str, slot: int) -> VibeSnapshot:
    last_v = vibe_key_for_slot(channel_key, frequency, slot - SLOT_SECONDS)
    cur_v = vibe_key_for_slot(channel_key, frequency, slot)
    next_v = vibe_key_for_slot(channel_key, frequency, slot + SLOT_SECONDS)
    tags = {
        proto: (
            nostr_filter_tag(last_v, proto),
            nostr_filter_tag(cur_v, proto),
            nostr_filter_tag(next_v, proto),
        )
        for proto in MESSAGE_PROTOCOLS.values()
    }
    return VibeSnapshot(
        slot=slot,
        last=last_v,
        current=cur_v,
        next=next_v,
        body_last=expand_body_key(last_v),
        body_current=expand_body_key(cur_v),
        body_next=expand_body_key(next_v),
        presence_last=expand_presence_key(last_v),
        presence_current=expand_presence_key(cur_v),
        presence_next=expand_presence_key(next_v),
        tags_by_protocol=tags,
    )


class VibeKeys:
    """Hold last, current, and next vibe keys, derived keys, and Nostr tags; rotate every 5 minutes."""

    def __init__(self, channel_key: str, frequency: str) -> None:
        self._lock = threading.RLock()
        self._channel_key = channel_key
        self._frequency = frequency
        self._room_id = room_id_16(frequency)
        self._snapshot: VibeSnapshot | None = None
        self.refresh()

    def set_credentials(self, channel_key: str, frequency: str) -> None:
        with self._lock:
            self._channel_key = channel_key
            self._frequency = frequency
            self._room_id = room_id_16(frequency)
            self._snapshot = None
            self.refresh()

    def refresh(self, unix_time: float | int | None = None) -> VibeSnapshot:
        with self._lock:
            slot = slot_for_time(unix_time)
            if self._snapshot is not None and self._snapshot.slot == slot:
                return self._snapshot
            self._snapshot = _build_snapshot(self._channel_key, self._frequency, slot)
            return self._snapshot

    def snapshot(self) -> VibeSnapshot:
        with self._lock:
            assert self._snapshot is not None
            return self._snapshot

    def candidate_body_keys(self) -> tuple[bytes, bytes, bytes]:
        return self.refresh().candidate_body_keys()

    def candidate_presence_keys(self) -> tuple[bytes, bytes, bytes]:
        return self.refresh().candidate_presence_keys()

    @property
    def room_id(self) -> bytes:
        """Cached 16-byte public header filter for the current frequency dial."""
        return self._room_id
