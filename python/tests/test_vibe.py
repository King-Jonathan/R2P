"""Vibe key derivation tests."""

from r2p.crypto.vibe import (
    VibeKeys,
    normalize_16,
    room_id_16,
    slot_for_time,
    vibe_key_for_slot,
)


def test_normalize_16_pad():
    assert len(normalize_16("liberty")) == 16
    assert normalize_16("liberty") == b"liberty" + b"\x00" * 9


def test_normalize_16_hash_long():
    long = "x" * 40
    out = normalize_16(long)
    assert len(out) == 16
    assert out == normalize_16(long)


def test_vibe_deterministic():
    slot = 1_700_000_000
    slot = (slot // 300) * 300
    a = vibe_key_for_slot("liberty", "7.074", slot)
    b = vibe_key_for_slot("liberty", "7.074", slot)
    assert a == b
    assert len(a) == 16


def test_vibe_changes_with_slot():
    slot = slot_for_time(1_700_000_000)
    a = vibe_key_for_slot("liberty", "7.074", slot)
    b = vibe_key_for_slot("liberty", "7.074", slot + 300)
    assert a != b


def test_vibe_keys_trio():
    vk = VibeKeys("liberty", "7.074")
    snap = vk.refresh(1_700_000_100)
    assert snap.last != snap.current
    assert snap.next != snap.current
    assert len(vk.candidate_body_keys()) == 3
    assert len(vk.candidate_presence_keys()) == 3


def test_room_id_16_not_clear_frequency():
    rid = room_id_16("7.074")
    assert len(rid) == 16
    assert rid == room_id_16("7.074")
    # Must not place zero-padded dial string on the wire.
    assert rid != normalize_16("7.074")
    assert b"7.074" not in rid
    vk = VibeKeys("liberty", "7.074")
    assert vk.room_id == rid
