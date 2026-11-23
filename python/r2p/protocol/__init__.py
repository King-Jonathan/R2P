"""Wire protocol: packets, chunking, dedup."""

from r2p.protocol.chunking import (
    MAX_CHUNK_BODY,
    build_message_body,
    chunk_body,
    is_final_chunk,
)
from r2p.protocol.dedup import DedupCache
from r2p.protocol.packet import (
    HEADER_BYTES,
    MAX_BODY,
    PAD_MAX,
    PAD_MIN,
    PROTOCOL_PIXEL,
    PROTOCOL_SPECTROGRAM,
    PROTOCOL_DISCOVERY,
    Packet,
    pack_header_and_body,
    pack_packet,
    unpack_packet,
)

__all__ = [
    "HEADER_BYTES",
    "MAX_BODY",
    "MAX_CHUNK_BODY",
    "PAD_MAX",
    "PAD_MIN",
    "PROTOCOL_PIXEL",
    "PROTOCOL_SPECTROGRAM",
    "PROTOCOL_DISCOVERY",
    "DedupCache",
    "Packet",
    "build_message_body",
    "chunk_body",
    "is_final_chunk",
    "pack_header_and_body",
    "pack_packet",
    "unpack_packet",
]
