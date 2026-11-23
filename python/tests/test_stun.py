"""STUN Binding Success parse (XOR-MAPPED IPv4)."""

from r2p.discovery.stun_client import is_stun_response, parse_mapped_address
from r2p.protocol.packet import unpack_packet

STUN_HEX = "0101000c2112a4421111111111111111111111110020000800016a74ea12d543"


def test_parse_xor_mapped_ipv4():
    data = bytes.fromhex(STUN_HEX)
    tx = b"\x11" * 12
    assert is_stun_response(data)
    assert parse_mapped_address(data, tx) == ("203.0.113.1", 19302)
    assert parse_mapped_address(data, b"\x22" * 12) is None


def test_stun_datagram_is_not_chat():
    data = bytes.fromhex(STUN_HEX)
    assert unpack_packet(data) is None
    padded = data + b"\x00" * (200 - len(data))
    # protocol byte 0x01 is discovery, but body_len/chunk will not be a valid chat layout we care
    # about; size is 200 so unpack may return something. STUN type 0x0101 means first two
    # bytes 01 01: protocol=1 (ok), room starts with 01...
    # Recv loop classifies STUN before unpack. Parser still must not explode.
    unpack_packet(padded)  # no throw
