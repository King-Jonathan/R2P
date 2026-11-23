#!/usr/bin/env python3
"""Publish one KIND 20001 event to each default relay and print OK/reject."""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from r2p.config import DEFAULT_RELAYS
from r2p.crypto.vibe import VibeKeys
from r2p.crypto.cipher import nostr_filter_tag
from r2p.discovery.nostr_backend import KIND_EPHEMERAL, NostrDiscoveryBackend, build_event
from r2p.protocol.packet import PROTOCOL_PIXEL


async def probe(url: str, timeout: float = 12.0) -> str:
    from websockets.asyncio.client import connect as ws_connect

    vibe = VibeKeys("probe-channel", "probe-freq")
    backend = NostrDiscoveryBackend(relays=[], vibe=vibe, protocol=PROTOCOL_PIXEL, get_presence=lambda: None)
    snap = vibe.snapshot()
    event = build_event(
        backend._priv,
        backend._pub_hex,
        KIND_EPHEMERAL,
        [["t", nostr_filter_tag(snap.current, PROTOCOL_PIXEL)]],
        "AA==",
    )
    payload = json.dumps(["EVENT", event])
    try:
        async with ws_connect(url, open_timeout=8, close_timeout=2) as ws:
            await ws.send(payload)
            deadline = time.time() + timeout
            while time.time() < deadline:
                remaining = max(0.1, deadline - time.time())
                raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                msg = json.loads(raw)
                if isinstance(msg, list) and msg and msg[0] == "OK":
                    ok = bool(msg[2]) if len(msg) > 2 else False
                    reason = msg[3] if len(msg) > 3 else ""
                    return f"{url}: OK {ok} {reason}".strip()
                if isinstance(msg, list) and msg and msg[0] == "NOTICE":
                    return f"{url}: NOTICE {msg[1] if len(msg) > 1 else ''}"
            return f"{url}: timeout (no OK)"
    except Exception as exc:
        return f"{url}: error {type(exc).__name__}: {exc}"


async def main() -> int:
    relays = DEFAULT_RELAYS
    results = []
    for url in relays:
        line = await probe(url)
        print(line)
        results.append(line)
    ok_any = any(": OK True" in r for r in results)
    return 0 if ok_any else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
