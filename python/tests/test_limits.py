"""Assembler, dedup, and peer caps."""

from r2p.discovery.peer_list import MAX_PEERS, PeerList
from r2p.protocol.chunking import MAX_PENDING, MessageAssembler
from r2p.protocol.dedup import DedupCache


def test_assembler_caps_pending():
    asm = MessageAssembler()
    t0 = 1_000.0
    for i in range(MAX_PENDING + 5):
        mid = bytes([i]) + b"\x00" * 5
        asm.feed(mid, 0, b"x" * 200, now=t0)
    assert asm.pending_count() == MAX_PENDING
    # The oldest message was evicted; the newest message can still complete.
    newest = bytes([MAX_PENDING + 4]) + b"\x00" * 5
    assert asm.feed(newest, 1, b"end", now=t0 + 1) == b"x" * 200 + b"end"
    assert asm.feed(b"\x00" * 6, 1, b"end", now=t0 + 1) is None


def test_assembler_ttl():
    asm = MessageAssembler()
    asm.feed(b"msgid!", 0, b"x" * 200, now=100.0)
    assert asm.pending_count() == 1
    asm.feed(b"msgid!", 0, b"x" * 200, now=150.0)
    asm.purge(now=159.9)
    assert asm.pending_count() == 1
    asm.purge(now=160.0)
    assert asm.pending_count() == 0


def test_dedup_caps_ids():
    cache = DedupCache(ttl_seconds=600.0, max_ids=8)
    t = 50.0
    for i in range(20):
        cache.is_duplicate(bytes([i]) + b"\x00" * 5, 0, now=t)
    assert cache.size() == 8
    newest = bytes([19]) + b"\x00" * 5
    assert cache.is_duplicate(newest, 0, now=t + 599.9)
    assert not cache.is_duplicate(newest, 1, now=t + 599.9)
    assert not cache.is_duplicate(newest, 0, now=t + 600.0)
    assert cache.is_duplicate(newest, 0, now=t + 600.0)
    assert not cache.is_duplicate(newest, 1, now=t + 600.0)
    assert cache.is_duplicate(newest, 65535, now=t + 600.0)
    cache.purge(now=t + 600.0)
    assert cache.size() == 1


def test_peer_list_caps():
    peers = PeerList()
    for i in range(MAX_PEERS + 10):
        peers.add("10.0.0.1", 10000 + i, now=float(i))
    assert len(peers.all()) == MAX_PEERS
