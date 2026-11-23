"""Binary discovery presence encode/decode, address pick, and self-filter."""

from r2p.discovery.peer_list import PeerList
from r2p.discovery.presence import (
    MAX_PRESENCE_ENDPOINTS,
    decode_presence,
    encode_presence,
    pick_send_addr,
    shares_lan,
)


def test_format_parse_roundtrip():
    inst = bytes.fromhex("aabbccddeeff0011")
    eps = [("203.0.113.1", 19302), ("192.168.1.5", 19302)]
    raw = encode_presence(inst, eps)
    assert len(raw) == 9 + 6 * 2
    assert decode_presence(raw) == (inst, eps)


def test_format_drops_loopback_and_dupes():
    inst = bytes.fromhex("aabbccddeeff0011")
    raw = encode_presence(
        inst,
        [
            ("127.0.0.1", 19302),
            ("192.168.1.5", 19302),
            ("192.168.1.5", 19302),
            ("0.0.0.0", 9),
        ] + [(f"10.0.0.{i}", 19302) for i in range(1, 20)],
    )
    parsed = decode_presence(raw)
    assert parsed is not None
    assert parsed[0] == inst
    assert len(parsed[1]) == MAX_PRESENCE_ENDPOINTS
    assert parsed[1][0] == ("192.168.1.5", 19302)


def test_parse_rejects_loopback_endpoint():
    inst = bytes.fromhex("aabbccddeeff0011")
    # 127.0.0.1:19302 in binary
    bad_loopback = inst + bytes([1, 127, 0, 0, 1, 0x4B, 0x66])
    assert decode_presence(bad_loopback) is None
    # Trailing byte rejected
    good = encode_presence(inst, [("192.168.1.5", 19302)])
    assert decode_presence(good + b"\x00") is None


def test_parse_rejects_short_instance():
    assert decode_presence(b"\x01\x02\x03\x04") is None
    assert decode_presence(bytes(8) + bytes([0])) is None


def test_shares_lan_slash24():
    assert shares_lan("192.168.1.20", {"192.168.1.10"})
    assert not shares_lan("192.168.2.20", {"192.168.1.10"})
    assert not shares_lan("203.0.113.9", {"192.168.1.10"})


def test_pick_same_nat_different_hosts():
    addr = pick_send_addr(
        their_endpoints=[("203.0.113.9", 19302), ("192.168.1.20", 19302)],
        our_public="203.0.113.9",
        our_locals={"192.168.1.10"},
        our_port=19302,
        our_endpoints={
            ("203.0.113.9", 19302),
            ("192.168.1.10", 19302),
            ("127.0.0.1", 19302),
        },
    )
    assert addr == ("192.168.1.20", 19302)


def test_pick_same_host_uses_loopback():
    addr = pick_send_addr(
        their_endpoints=[("203.0.113.9", 19303), ("192.168.1.10", 19303)],
        our_public="203.0.113.9",
        our_locals={"192.168.1.10"},
        our_port=19302,
        our_endpoints={
            ("203.0.113.9", 19302),
            ("192.168.1.10", 19302),
            ("127.0.0.1", 19302),
        },
    )
    assert addr == ("127.0.0.1", 19303)


def test_pick_same_public_other_port_without_lan_uses_loopback():
    addr = pick_send_addr(
        their_endpoints=[("203.0.113.9", 19303)],
        our_public="203.0.113.9",
        our_locals={"192.168.1.10"},
        our_port=19302,
        our_endpoints={
            ("203.0.113.9", 19302),
            ("192.168.1.10", 19302),
            ("127.0.0.1", 19302),
        },
    )
    assert addr == ("127.0.0.1", 19303)


def test_pick_different_nat_uses_public_ignores_private():
    addr = pick_send_addr(
        their_endpoints=[("198.51.100.7", 19302), ("10.0.0.5", 19302)],
        our_public="203.0.113.9",
        our_locals={"192.168.1.10"},
        our_port=19302,
        our_endpoints={("203.0.113.9", 19302), ("192.168.1.10", 19302)},
    )
    assert addr == ("198.51.100.7", 19302)


def test_pick_same_public_same_port_only_is_self():
    addr = pick_send_addr(
        their_endpoints=[("203.0.113.9", 19302)],
        our_public="203.0.113.9",
        our_locals={"192.168.1.10"},
        our_port=19302,
        our_endpoints={("203.0.113.9", 19302), ("192.168.1.10", 19302)},
    )
    assert addr is None


def test_pick_lan_only_when_stun_missing():
    addr = pick_send_addr(
        their_endpoints=[("192.168.1.20", 19302)],
        our_public=None,
        our_locals={"192.168.1.10"},
        our_port=19302,
        our_endpoints={("192.168.1.10", 19302)},
    )
    assert addr == ("192.168.1.20", 19302)


def test_peer_list_skips_any_self_endpoint():
    peers = PeerList()
    peers.replace_self({("203.0.113.9", 19302), ("192.168.1.10", 19302)})
    assert peers.add("203.0.113.9", 19302) is False
    assert peers.add("192.168.1.10", 19302) is False
    assert peers.add("192.168.1.20", 19302) is True
    assert peers.all() == [("192.168.1.20", 19302)]


def test_peer_list_replace_self_drops_old_port():
    peers = PeerList()
    peers.replace_self({("192.168.1.10", 19302)})
    assert peers.add("192.168.1.10", 19302) is False
    peers.replace_self({("192.168.1.10", 19303)})
    assert peers.add("192.168.1.10", 19302) is True
    assert peers.add("192.168.1.10", 19303) is False


def test_ingest_presence_skips_own_instance_and_adds_lan_peer():
    from pathlib import Path

    from r2p.app_core import AppCore
    from r2p.config import Config

    root = Path(__file__).resolve().parents[1]
    cfg = Config(
        discovery_backend="lan",
        encodings_path=str(root / "encodings.json"),
        udp_port=19302,
    )
    core = AppCore(cfg)
    try:
        core._public_ip = "203.0.113.9"
        core._remember_self_endpoints()
        own = encode_presence(core._instance_id, [("203.0.113.9", 19302), ("10.255.250.10", 19302)])
        core.ingest_presence(own)
        assert core.peer_count() == 0
        other = encode_presence(
            bytes.fromhex("aabbccddeeff0011"),
            [("203.0.113.9", 19302), ("10.255.250.20", 19302)],
        )
        core.ingest_presence(other)
        assert ("10.255.250.20", 19302) in core.peers.all()
        assert ("203.0.113.9", 19302) not in core.peers.all()
    finally:
        core.stop()
