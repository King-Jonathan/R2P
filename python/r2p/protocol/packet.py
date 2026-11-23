"""Byte-aligned UDP packet (authenticated with ChaCha20-Poly1305)."""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass

PROTOCOL_PIXEL = 0
PROTOCOL_DISCOVERY = 1
PROTOCOL_SPECTROGRAM = 2
MESSAGE_PROTOCOLS = {"pixel": PROTOCOL_PIXEL, "spectrogram": PROTOCOL_SPECTROGRAM}
PROTOCOLS = (PROTOCOL_PIXEL, PROTOCOL_DISCOVERY, PROTOCOL_SPECTROGRAM)
MAX_CHUNK_ID = 65535

# protocol(1) + room_id(16) + message_id(6) + chunk_id(2) + body_len(1)
HEADER = struct.Struct("!B16s6sHB")
HEADER_BYTES = HEADER.size

PAD_MIN = 200
PAD_MAX = 300
MAX_BODY = 255


@dataclass(frozen=True)
class Packet:
    protocol: int  # 0 pixel, 1 discovery, 2 spectrogram
    room_id: bytes  # 16 bytes public filter (hash of frequency; not dial string)
    message_id: bytes  # 6 bytes
    chunk_id: int  # 0..65535 (wire u16)
    body: bytes  # authenticated ciphertext, length 0..255


def pack_header(
    protocol: int,
    room_id: bytes,
    message_id: bytes,
    chunk_id: int,
    body_len: int,
) -> bytes:
    """Pack and validate the 26-byte header (also used as AEAD AAD)."""
    if protocol not in PROTOCOLS:
        raise ValueError("unknown protocol")
    if len(room_id) != 16:
        raise ValueError("room_id must be 16 bytes")
    if len(message_id) != 6:
        raise ValueError("message_id must be 6 bytes")
    if not (0 <= chunk_id <= MAX_CHUNK_ID):
        raise ValueError("chunk_id must fit in 0..65535")
    if not (0 <= body_len <= MAX_BODY):
        raise ValueError("body longer than 255 bytes")
    return HEADER.pack(protocol, room_id, message_id, chunk_id, body_len)


def packet_aad(packet: Packet) -> bytes:
    return pack_header(
        packet.protocol,
        packet.room_id,
        packet.message_id,
        packet.chunk_id,
        len(packet.body),
    )


def pack_header_and_body(packet: Packet) -> bytes:
    return packet_aad(packet) + packet.body


def pack_packet(packet: Packet, pad_to: int | None = None) -> bytes:
    """Pack packet and add random padding so total length is in [200, 300]."""
    core = pack_header_and_body(packet)
    if len(core) > PAD_MAX:
        raise ValueError("packet core exceeds max pad size")
    if pad_to is None:
        lo = max(PAD_MIN, len(core))
        hi = PAD_MAX
        pad_to = secrets.randbelow(hi - lo + 1) + lo
    if pad_to < len(core) or pad_to > PAD_MAX:
        raise ValueError("invalid pad_to")
    padding = secrets.token_bytes(pad_to - len(core))
    return core + padding


def unpack_packet(data: bytes) -> Packet | None:
    """Parse a packet. Return None on hard format errors (caller silent-drops)."""
    if not (PAD_MIN <= len(data) <= PAD_MAX):
        return None
    if len(data) < HEADER_BYTES:
        return None
    protocol, room_id, message_id, chunk_id, body_len = HEADER.unpack_from(data)
    if protocol not in PROTOCOLS:
        return None
    end = HEADER_BYTES + body_len
    if end > len(data):
        return None
    return Packet(
        protocol=protocol,
        room_id=room_id,
        message_id=message_id,
        chunk_id=chunk_id,
        body=data[HEADER_BYTES:end],
    )


def new_message_id() -> bytes:
    return secrets.token_bytes(6)
