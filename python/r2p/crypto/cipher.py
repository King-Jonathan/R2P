"""RFC 8439 ChaCha20-Poly1305 AEAD for packet bodies and discovery presence,
plus HMAC-SHA256 for Nostr filter tags.

HKDF salt=None means RFC 5869 HashLen zero salt (32 0x00 bytes).
"""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from r2p.protocol.packet import MAX_CHUNK_ID, MESSAGE_PROTOCOLS, PROTOCOLS

NONCE_BYTES = 12
AEAD_TAG_BYTES = 16
PRESENCE_AAD = b"r2p-presence-v2"


def nostr_filter_tag(vibe_key: bytes, protocol: int) -> str:
    """Derive a repeatable 64-hex-char Nostr filter tag via HMAC-SHA256."""
    if len(vibe_key) != 16 or protocol not in MESSAGE_PROTOCOLS.values():
        raise ValueError("invalid vibe key or chat protocol")
    return hmac.new(
        vibe_key,
        b"r2p-nostr-tag-v2:" + bytes([protocol]),
        hashlib.sha256,
    ).hexdigest()


def expand_body_key(vibe_key: bytes) -> bytes:
    """Expand 16-byte vibe key to 32-byte ChaCha20-Poly1305 body key."""
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"r2p-body-v2",
    ).derive(vibe_key)


def expand_presence_key(vibe_key: bytes) -> bytes:
    """Expand 16-byte vibe key to 32-byte ChaCha20-Poly1305 presence key."""
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"r2p-presence-v2",
    ).derive(vibe_key)


def _nonce_for_chunk(message_id: bytes, chunk_id: int, protocol: int) -> bytes:
    if not 0 <= chunk_id <= MAX_CHUNK_ID or protocol not in PROTOCOLS:
        raise ValueError("invalid chunk or protocol")
    material = message_id + chunk_id.to_bytes(2, "big") + bytes([protocol]) + b"r2p-body-v2"
    return hashlib.sha256(material).digest()[:NONCE_BYTES]


def body_encrypt(
    body_key: bytes,
    message_id: bytes,
    chunk_id: int,
    plaintext: bytes,
    protocol: int,
    aad: bytes,
) -> bytes:
    """Authenticate header (aad) and encrypt chunk body with ChaCha20-Poly1305."""
    nonce = _nonce_for_chunk(message_id, chunk_id, protocol)
    return ChaCha20Poly1305(body_key).encrypt(nonce, plaintext, aad)


def body_decrypt(
    body_key: bytes,
    message_id: bytes,
    chunk_id: int,
    ciphertext: bytes,
    protocol: int,
    aad: bytes,
) -> bytes | None:
    """Verify AAD/tag and decrypt body. Return None on wrong key or tampering."""
    if len(ciphertext) < AEAD_TAG_BYTES:
        return None
    nonce = _nonce_for_chunk(message_id, chunk_id, protocol)
    try:
        return ChaCha20Poly1305(body_key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        return None


def endpoint_encrypt(presence_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt presence. Returns 12-byte random nonce || ciphertext || 16-byte tag."""
    nonce = os.urandom(NONCE_BYTES)
    return nonce + ChaCha20Poly1305(presence_key).encrypt(nonce, plaintext, PRESENCE_AAD)


def endpoint_decrypt(presence_key: bytes, ciphertext: bytes) -> bytes | None:
    """Decrypt and verify presence. Return None on wrong key or tampering."""
    if len(ciphertext) < NONCE_BYTES + AEAD_TAG_BYTES:
        return None
    try:
        return ChaCha20Poly1305(presence_key).decrypt(
            ciphertext[:NONCE_BYTES], ciphertext[NONCE_BYTES:], PRESENCE_AAD,
        )
    except InvalidTag:
        return None
