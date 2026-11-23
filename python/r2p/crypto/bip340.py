"""Minimal pure-Python BIP-340 Schnorr over secp256k1 for Nostr event signatures."""

from __future__ import annotations

import hashlib
import os

# secp256k1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _mod_inv(a: int, m: int) -> int:
    return pow(a, -1, m)


def _point_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 * _mod_inv(2 * y1, P)) % P
    else:
        lam = ((y2 - y1) * _mod_inv((x2 - x1) % P, P)) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return x3, y3


def _point_mul(k: int, point: tuple[int, int] | None = (Gx, Gy)) -> tuple[int, int] | None:
    k = k % N
    result: tuple[int, int] | None = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode("utf-8")).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def _bytes32(i: int) -> bytes:
    return i.to_bytes(32, "big")


def _int_from(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _lift_x(x: int) -> tuple[int, int] | None:
    if x >= P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y * y) % P != y2:
        return None
    if y & 1:
        y = P - y
    return x, y


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (privkey_32, xonly_pubkey_32)."""
    while True:
        priv = os.urandom(32)
        d = _int_from(priv)
        if not (1 <= d < N):
            continue
        point = _point_mul(d)
        if point is None:
            continue
        x, y = point
        if y & 1:
            d = N - d
            priv = _bytes32(d)
        return priv, _bytes32(x)


def schnorr_sign(message_hash32: bytes, privkey: bytes) -> bytes:
    """BIP-340 sign; message_hash32 is 32-byte message (for Nostr: event id)."""
    if len(message_hash32) != 32 or len(privkey) != 32:
        raise ValueError("bad lengths")
    d0 = _int_from(privkey)
    if not (1 <= d0 < N):
        raise ValueError("bad privkey")
    P_pt = _point_mul(d0)
    if P_pt is None:
        raise ValueError("bad point")
    px, py = P_pt
    d = d0 if (py % 2 == 0) else (N - d0)
    pubkey = _bytes32(px)
    aux = os.urandom(32)
    t = _bytes32(d ^ _int_from(_tagged_hash("BIP0340/aux", aux)))
    rand = _tagged_hash("BIP0340/nonce", t + pubkey + message_hash32)
    k0 = _int_from(rand) % N
    if k0 == 0:
        raise ValueError("nonce fail")
    R = _point_mul(k0)
    if R is None:
        raise ValueError("R fail")
    rx, ry = R
    k = k0 if (ry % 2 == 0) else (N - k0)
    e = _int_from(_tagged_hash("BIP0340/challenge", _bytes32(rx) + pubkey + message_hash32)) % N
    s = (k + e * d) % N
    return _bytes32(rx) + _bytes32(s)


def schnorr_verify(message_hash32: bytes, signature: bytes, pubkey_xonly: bytes) -> bool:
    if len(message_hash32) != 32 or len(signature) != 64 or len(pubkey_xonly) != 32:
        return False
    px = _int_from(pubkey_xonly)
    P_pt = _lift_x(px)
    if P_pt is None:
        return False
    rx = _int_from(signature[:32])
    s = _int_from(signature[32:])
    if rx >= P or s >= N:
        return False
    e = _int_from(_tagged_hash("BIP0340/challenge", signature[:32] + pubkey_xonly + message_hash32)) % N
    # R = s*G - e*P
    sG = _point_mul(s)
    eP = _point_mul(e, P_pt)
    if eP is None or sG is None:
        return False
    # negate eP
    eP_neg = (eP[0], P - eP[1]) if eP[1] != 0 else eP
    R = _point_add(sG, eP_neg)
    if R is None:
        return False
    if R[1] % 2 != 0:
        return False
    return R[0] == rx
