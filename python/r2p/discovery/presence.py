"""Binary discovery presence: 8-byte instance_id plus candidate IPv4 endpoints."""

from __future__ import annotations

import socket
import struct

INSTANCE_ID_BYTES = 8
MAX_PRESENCE_ENDPOINTS = 8
_ENDPOINT_STRUCT = struct.Struct("!4sH")


def is_ipv4(host: str) -> bool:
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def is_private_ipv4(host: str) -> bool:
    if not is_ipv4(host):
        return False
    o = [int(p) for p in host.split(".")]
    if o[0] == 10:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    return False


def _usable_endpoint(host: str, port: int) -> tuple[bytes, int] | None:
    if not (1 <= port <= 65535) or not host or not is_ipv4(host):
        return None
    if host.startswith("127.") or host == "0.0.0.0":
        return None
    return socket.inet_aton(host), port


def encode_presence(instance_id: bytes, endpoints: list[tuple[str, int]]) -> bytes:
    """Pack binary presence: instance_id(8) || count(1) || count*(ipv4(4)+port(2))."""
    if len(instance_id) != INSTANCE_ID_BYTES:
        raise ValueError("instance_id must be 8 bytes")
    packed: list[bytes] = []
    seen: set[tuple[bytes, int]] = set()
    for host, port in endpoints:
        usable = _usable_endpoint(host, int(port))
        if usable is None or usable in seen:
            continue
        seen.add(usable)
        packed.append(_ENDPOINT_STRUCT.pack(usable[0], usable[1]))
        if len(packed) >= MAX_PRESENCE_ENDPOINTS:
            break
    if not packed:
        return b""
    return instance_id + bytes([len(packed)]) + b"".join(packed)


def decode_presence(data: bytes) -> tuple[bytes, list[tuple[str, int]]] | None:
    """Parse binary presence. Return None on invalid length, count, or endpoints."""
    if len(data) < INSTANCE_ID_BYTES + 1:
        return None
    instance_id = data[:INSTANCE_ID_BYTES]
    count = data[INSTANCE_ID_BYTES]
    if not (1 <= count <= MAX_PRESENCE_ENDPOINTS):
        return None
    expected = INSTANCE_ID_BYTES + 1 + count * _ENDPOINT_STRUCT.size
    if len(data) != expected:
        return None
    endpoints: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    offset = INSTANCE_ID_BYTES + 1
    for _ in range(count):
        raw_ip, port = _ENDPOINT_STRUCT.unpack_from(data, offset)
        offset += _ENDPOINT_STRUCT.size
        if port == 0 or raw_ip[0] == 127 or raw_ip == b"\x00\x00\x00\x00":
            return None
        ep = (socket.inet_ntoa(raw_ip), port)
        if ep not in seen:
            seen.add(ep)
            endpoints.append(ep)
    if not endpoints:
        return None
    return instance_id, endpoints


def _ipv4_slash24(host: str) -> bytes | None:
    if not is_ipv4(host):
        return None
    return socket.inet_aton(host)[:3]


def shares_lan(host: str, local_ips: set[str]) -> bool:
    """True when host is RFC1918 and shares a /24 with one of our local IPv4s."""
    if not is_private_ipv4(host):
        return False
    host_net = _ipv4_slash24(host)
    if host_net is None:
        return False
    for local in local_ips:
        if not is_private_ipv4(local):
            continue
        if _ipv4_slash24(local) == host_net:
            return True
    return False


def pick_send_addr(
    their_endpoints: list[tuple[str, int]],
    our_public: str | None,
    our_locals: set[str],
    our_port: int,
    our_endpoints: set[tuple[str, int]],
) -> tuple[str, int] | None:
    """
    Choose one reachable IPv4 send target from a peer's advertised endpoints.

    Prefer a same-host loopback rewrite, then a same-LAN address, then public IPv4.
    Drop endpoints that are this process.
    """
    candidates = [(h, p) for h, p in their_endpoints if (h, p) not in our_endpoints]
    if not candidates:
        return None

    for host, port in candidates:
        if port == our_port:
            continue
        if host in our_locals:
            return ("127.0.0.1", port)

    for host, port in candidates:
        if shares_lan(host, our_locals):
            return (host, port)

    if our_public:
        advertised_same_nat = any(h == our_public for h, _p in their_endpoints)
        if advertised_same_nat:
            for host, port in candidates:
                if host != our_public and is_ipv4(host):
                    return (host, port)
            for host, port in candidates:
                if host == our_public and port != our_port:
                    return ("127.0.0.1", port)

    for host, port in candidates:
        if host == our_public:
            continue
        if is_ipv4(host) and not is_private_ipv4(host):
            return (host, port)

    for host, port in candidates:
        if is_ipv4(host):
            return (host, port)
    return None


def local_ipv4_addresses() -> list[str]:
    """IPv4 addresses on this host (excluding loopback), default-route IP first."""
    ips: set[str] = set()
    primary = primary_ipv4()
    if primary:
        ips.add(primary)
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if is_ipv4(ip) and not ip.startswith("127.") and ip != "0.0.0.0":
                ips.add(ip)
    except OSError:
        pass
    ordered = sorted(ips - ({primary} if primary else set()))
    return ([primary] if primary else []) + ordered


def primary_ipv4() -> str | None:
    """IPv4 of the default route, if it is not loopback."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None
    if is_ipv4(ip) and not ip.startswith("127.") and ip != "0.0.0.0":
        return ip
    return None
