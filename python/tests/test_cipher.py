"""ChaCha20-Poly1305 AEAD body/presence crypto, Nostr tags, and BIP-340 tests."""

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from r2p.crypto.bip340 import generate_keypair, schnorr_sign, schnorr_verify
from r2p.crypto.cipher import (
    AEAD_TAG_BYTES,
    NONCE_BYTES,
    PRESENCE_AAD,
    body_decrypt,
    body_encrypt,
    endpoint_decrypt,
    endpoint_encrypt,
    expand_body_key,
    expand_presence_key,
    nostr_filter_tag,
)
from r2p.crypto.vibe import vibe_key_for_slot
from r2p.protocol.packet import pack_header


def test_body_roundtrip():
    vibe = vibe_key_for_slot("liberty", "7.074", 1_700_000_000)
    key = expand_body_key(vibe)
    wrong = expand_body_key(vibe_key_for_slot("other", "7.074", 1_700_000_000))
    mid = b"msgid!"
    room = b"\xaa" * 16
    plain = b"\x01\x02\x03hello"
    aad = pack_header(0, room, mid, 0, len(plain) + AEAD_TAG_BYTES)
    c = body_encrypt(key, mid, 0, plain, 0, aad)
    assert len(c) == len(plain) + AEAD_TAG_BYTES
    assert body_decrypt(key, mid, 0, c, 0, aad) == plain
    assert body_decrypt(wrong, mid, 0, c, 0, aad) is None
    # Tampered ciphertext or tampered AAD must fail authentication.
    flipped = bytes([c[0] ^ 1]) + c[1:]
    assert body_decrypt(key, mid, 0, flipped, 0, aad) is None
    bad_aad = pack_header(0, b"\xbb" * 16, mid, 0, len(plain) + AEAD_TAG_BYTES)
    assert body_decrypt(key, mid, 0, c, 0, bad_aad) is None


# Frozen v2 HKDF-SHA256 / RFC 8439 ChaCha20-Poly1305 / HMAC-SHA256 vectors (slot 1700000000).
VIBE_HEX = "7bb4577b91389b34a6b9e48323c51c49"
EKEY_HEX = "40d45e43ce1b6b85456a1bb3614c822cc4281bbc2a0b7d3bf082d4d2e0622ff0"
PKEY_HEX = "97d67c671b09a22f8f5f44d30b4a0ddc3c48dcdebe68bc200ce7e1e47acdb901"
BODY0_HEX = "9bc42afa91a4af4eb028ceccc3be34bd6cc620489b725459"
BODY1_HEX = "47dbd42521ce67c0f332f510df2d8ed747d868625c8a5946"
ENDPT_HEX = "000102030405060708090a0ba83e2091bfbfa4c9966001d2afbadaebd2b3669d5815d282166f8dd461a5b1d6e2"
TAG0_HEX = "476d13db94e46e0e4156a0e60033888c57315b4978fd254b1ee4d2fcd0d0d0ac"
TAG2_HEX = "1ea961dda1a618578e3d883fe9f9c2ce5781ecca80dd7435e19e9959ef8b0f11"


def test_body_known_vector():
    vibe = vibe_key_for_slot("liberty", "7.074", 1_700_000_000)
    ekey = expand_body_key(vibe)
    pkey = expand_presence_key(vibe)
    assert vibe.hex() == VIBE_HEX
    assert ekey.hex() == EKEY_HEX
    assert pkey.hex() == PKEY_HEX
    assert nostr_filter_tag(vibe, 0) == TAG0_HEX
    assert nostr_filter_tag(vibe, 2) == TAG2_HEX
    mid = b"msgid!"
    room = b"\x11" * 16
    plain = b"\x01\x02\x03hello"
    aad0 = pack_header(0, room, mid, 0, len(plain) + AEAD_TAG_BYTES)
    aad1 = pack_header(1, room, mid, 0, len(plain) + AEAD_TAG_BYTES)
    assert body_encrypt(ekey, mid, 0, plain, 0, aad0).hex() == BODY0_HEX
    assert body_encrypt(ekey, mid, 0, plain, 1, aad1).hex() == BODY1_HEX


def test_protocol_binds_nonce():
    key = expand_body_key(vibe_key_for_slot("liberty", "7.074", 1_700_000_000))
    mid = b"msgid!"
    room = b"\x22" * 16
    plain = b"\x01\x02\x03hello"
    cases = [(chunk, protocol) for chunk in (0, 128, 256, 65535) for protocol in (0, 1, 2)]
    ciphertexts = [
        body_encrypt(
            key, mid, chunk, plain, protocol,
            pack_header(protocol, room, mid, chunk, len(plain) + AEAD_TAG_BYTES),
        )
        for chunk, protocol in cases
    ]
    assert len(set(ciphertexts)) == len(cases)
    for ciphertext, (chunk, protocol) in zip(ciphertexts, cases):
        aad = pack_header(protocol, room, mid, chunk, len(plain) + AEAD_TAG_BYTES)
        assert body_decrypt(key, mid, chunk, ciphertext, protocol, aad) == plain
        other_proto = (protocol + 1) % 3
        other_aad = pack_header(other_proto, room, mid, chunk, len(plain) + AEAD_TAG_BYTES)
        assert body_decrypt(key, mid, chunk, ciphertext, other_proto, other_aad) is None


def test_endpoint_random_nonce_and_roundtrip():
    key = expand_presence_key(b"\x11" * 16)
    plain = b"\x01\x02\x03\x04\x05\x06\x07\x08\x01\xcb\x00\x71\x05\x4b\x66"
    c1 = endpoint_encrypt(key, plain)
    c2 = endpoint_encrypt(key, plain)
    assert len(c1) == NONCE_BYTES + len(plain) + AEAD_TAG_BYTES
    assert c1[:NONCE_BYTES] != c2[:NONCE_BYTES]
    assert endpoint_decrypt(key, c1) == plain
    assert endpoint_decrypt(key, c2) == plain
    tampered = c1[:-1] + bytes([c1[-1] ^ 1])
    assert endpoint_decrypt(key, tampered) is None


def test_nostr_filter_encrypts_vibe_and_chat_protocol():
    import hashlib
    import hmac

    vibe = vibe_key_for_slot("liberty", "7.074", 1_700_000_000)
    for protocol in (0, 2):
        tag = nostr_filter_tag(vibe, protocol)
        assert tag == nostr_filter_tag(vibe, protocol)
        assert len(tag) == 64 and vibe.hex() not in tag
        expected = hmac.new(vibe, b"r2p-nostr-tag-v2:" + bytes([protocol]), hashlib.sha256).hexdigest()
        assert tag == expected
    assert nostr_filter_tag(vibe, 0) != nostr_filter_tag(vibe, 2)
    tags = [nostr_filter_tag(vibe, 0), nostr_filter_tag(vibe, 2)]
    for channel, frequency, slot in (
        ("other", "7.074", 1_700_000_000),
        ("liberty", "14.074", 1_700_000_000),
        ("liberty", "7.074", 1_700_000_300),
    ):
        assert nostr_filter_tag(vibe_key_for_slot(channel, frequency, slot), 0) not in tags
    for protocol in (1, 3):
        try:
            nostr_filter_tag(vibe, protocol)
        except ValueError:
            continue
        raise AssertionError("discovery and unknown protocols must not select a chat tag")


def test_endpoint_known_vector():
    vibe = vibe_key_for_slot("liberty", "7.074", 1_700_000_000)
    pkey = expand_presence_key(vibe)
    raw = bytes.fromhex(ENDPT_HEX)
    assert endpoint_decrypt(pkey, raw) == b"203.0.113.5:19302"
    nonce = bytes(range(NONCE_BYTES))
    built = nonce + ChaCha20Poly1305(pkey).encrypt(nonce, b"203.0.113.5:19302", PRESENCE_AAD)
    assert built.hex() == ENDPT_HEX
    # Wrong AAD / wrong key must reject.
    assert endpoint_decrypt(expand_body_key(vibe), built) is None


def test_schnorr():
    priv, pub = generate_keypair()
    msg = b"\xab" * 32
    sig = schnorr_sign(msg, priv)
    assert schnorr_verify(msg, sig, pub)
