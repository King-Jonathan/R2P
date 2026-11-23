"""Minimal STUN Binding client for public IP discovery."""

from __future__ import annotations

import os
import socket
import struct

STUN_MAGIC = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101


def _parse_host_port(server: str, default_port: int = 19302) -> tuple[str, int]:
    if ":" in server:
        host, _, port_s = server.rpartition(":")
        try:
            return host, int(port_s)
        except ValueError:
            return server, default_port
    return server, default_port


def build_binding_request(tx_id: bytes | None = None) -> tuple[bytes, bytes]:
    """Return (packet, 12-byte tx_id)."""
    tid = tx_id if tx_id is not None else os.urandom(12)
    if len(tid) != 12:
        raise ValueError("STUN tx id must be 12 bytes")
    packet = struct.pack("!HHI", STUN_BINDING_REQUEST, 0, STUN_MAGIC) + tid
    return packet, tid


def is_stun_response(data: bytes) -> bool:
    if len(data) < 20:
        return False
    r_type, _r_len, r_magic = struct.unpack("!HHI", data[:8])
    return r_magic == STUN_MAGIC and r_type == STUN_BINDING_SUCCESS


def parse_mapped_address(data: bytes, tx_id: bytes | None = None) -> tuple[str, int] | None:
    """Parse XOR-MAPPED-ADDRESS (preferred) or MAPPED-ADDRESS from a Binding Success."""
    if len(data) < 20:
        return None
    r_type, r_len, r_magic = struct.unpack("!HHI", data[:8])
    if r_magic != STUN_MAGIC or r_type != STUN_BINDING_SUCCESS:
        return None
    if tx_id is not None and data[8:20] != tx_id:
        return None

    offset = 20
    end = 20 + r_len
    if end > len(data):
        end = len(data)

    while offset + 4 <= end:
        atype, alen = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        if offset + alen > len(data):
            break
        value = data[offset : offset + alen]
        offset += alen
        offset += (4 - (alen % 4)) % 4

        if atype in (0x0020, 0x0001) and len(value) >= 4:
            family = value[1]
            if family == 0x01 and len(value) >= 8:
                raw_port = struct.unpack("!H", value[2:4])[0]
                raw_ip = value[4:8]
                if atype == 0x0020:
                    pub_port = raw_port ^ (STUN_MAGIC >> 16)
                    ip_int = struct.unpack("!I", raw_ip)[0] ^ STUN_MAGIC
                    pub_ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                else:
                    pub_port = raw_port
                    pub_ip = socket.inet_ntoa(raw_ip)
                return pub_ip, pub_port
    return None
