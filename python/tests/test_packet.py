"""Packet pack/unpack tests."""

from r2p.protocol.packet import (
    HEADER_BYTES,
    MAX_BODY,
    PAD_MAX,
    PAD_MIN,
    MAX_CHUNK_ID,
    PROTOCOL_SPECTROGRAM,
    Packet,
    pack_header_and_body,
    pack_packet,
    unpack_packet,
)


def test_roundtrip():
    pkt = Packet(
        protocol=0,
        room_id=b"\x01" * 16,
        message_id=b"abcdef",
        chunk_id=3,
        body=b"hello-world-bytes-xx",
    )
    raw = pack_packet(pkt)
    assert PAD_MIN <= len(raw) <= PAD_MAX
    out = unpack_packet(raw)
    assert out is not None
    assert out.protocol == 0
    assert out.room_id == pkt.room_id
    assert out.message_id == pkt.message_id
    assert out.chunk_id == 3
    assert out.body == pkt.body


def test_discovery_bit():
    pkt = Packet(
        protocol=1,
        room_id=b"\x02" * 16,
        message_id=b"123456",
        chunk_id=0,
        body=b"1.2.3.4:19302",
    )
    raw = pack_packet(pkt, pad_to=200)
    assert len(raw) == 200
    out = unpack_packet(raw)
    assert out is not None
    assert out.protocol == 1
    assert out.body == pkt.body


def test_bad_size_dropped():
    assert unpack_packet(b"\x00" * 50) is None
    assert unpack_packet(b"\x00" * 400) is None


def test_body_255_roundtrip():
    body = bytes(range(255))
    pkt = Packet(
        protocol=0,
        room_id=b"\x03" * 16,
        message_id=b"abcdef",
        chunk_id=0,
        body=body,
    )
    raw = pack_packet(pkt)
    out = unpack_packet(raw)
    assert out is not None
    assert out.body == body


def test_body_256_rejected():
    pkt = Packet(
        protocol=0,
        room_id=b"\x03" * 16,
        message_id=b"abcdef",
        chunk_id=0,
        body=b"\x00" * (MAX_BODY + 1),
    )
    try:
        pack_header_and_body(pkt)
    except ValueError:
        return
    raise AssertionError("256-byte body must not pack")


def test_known_answer_header_hex():
    pkt = Packet(
        protocol=0,
        room_id=b"\x01" * 16,
        message_id=b"abcdef",
        chunk_id=3,
        body=b"hello",
    )
    core = pack_header_and_body(pkt)
    assert len(core) == HEADER_BYTES + 5
    assert core.hex() == (
        "00"
        + "01" * 16
        + "616263646566"
        + "0003"
        + "05"
        + "68656c6c6f"
    )


def test_bad_protocol_and_truncated_body_dropped():
    base = bytearray(200)
    base[0] = 3
    assert unpack_packet(bytes(base)) is None
    base[0] = 0
    base[25] = 255
    assert unpack_packet(bytes(base)) is None


def test_spectrogram_packet_and_large_chunk_ids():
    for chunk_id in (128, 255, 256, MAX_CHUNK_ID):
        packet = Packet(PROTOCOL_SPECTROGRAM, b"r" * 16, b"msgid!", chunk_id, b"audio")
        assert unpack_packet(pack_packet(packet)) == packet
    for chunk_id in (-1, MAX_CHUNK_ID + 1):
        try:
            pack_packet(Packet(PROTOCOL_SPECTROGRAM, b"r" * 16, b"msgid!", chunk_id, b""))
        except ValueError:
            continue
        raise AssertionError("invalid chunk must not pack")


def test_dual_pack_repads():
    pkt = Packet(
        protocol=0,
        room_id=b"\x01" * 16,
        message_id=b"abcdef",
        chunk_id=1,
        body=b"same-body",
    )
    a = pack_packet(pkt)
    b = pack_packet(pkt)
    ua = unpack_packet(a)
    ub = unpack_packet(b)
    assert ua is not None and ub is not None
    assert ua.body == ub.body == pkt.body
    assert a != b
