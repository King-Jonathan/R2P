"""Nostr KIND 20001 ephemeral discovery (thin NIP-01 client)."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from websockets.asyncio.client import connect as ws_connect

from r2p.crypto.bip340 import generate_keypair, schnorr_sign, schnorr_verify
from r2p.crypto.cipher import endpoint_decrypt, endpoint_encrypt
from r2p.discovery.presence import decode_presence
from r2p.protocol.packet import MESSAGE_PROTOCOLS

if TYPE_CHECKING:
    from r2p.crypto.vibe import VibeKeys, VibeSnapshot

KIND_EPHEMERAL = 20001
PUBLISH_INTERVAL = 300.0  # 5 minutes while connected


def _serialize_event_id(pubkey_hex: str, created_at: int, kind: int, tags: list, content: str) -> bytes:
    payload = [0, pubkey_hex, created_at, kind, tags, content]
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).digest()


def verify_event(event: dict[str, Any]) -> bool:
    """Recompute NIP-01 id and BIP-340 sig. Drop on mismatch."""
    pubkey = event.get("pubkey")
    kind = event.get("kind")
    created_at = event.get("created_at")
    tags = event.get("tags")
    content = event.get("content")
    ev_id = event.get("id")
    sig = event.get("sig")
    if not isinstance(pubkey, str) or not isinstance(ev_id, str) or not isinstance(sig, str):
        return False
    if not isinstance(kind, int) or not isinstance(created_at, int):
        return False
    if not isinstance(tags, list) or not isinstance(content, str):
        return False
    try:
        want = _serialize_event_id(pubkey, created_at, kind, tags, content)
        got = bytes.fromhex(ev_id)
        sig_b = bytes.fromhex(sig)
        pub_b = bytes.fromhex(pubkey)
    except ValueError:
        return False
    if want != got:
        return False
    return schnorr_verify(got, sig_b, pub_b)


def build_event(privkey: bytes, pubkey_hex: str, kind: int, tags: list, content: str) -> dict[str, Any]:
    created_at = int(time.time())
    event_id = _serialize_event_id(pubkey_hex, created_at, kind, tags, content)
    sig = schnorr_sign(event_id, privkey)
    return {
        "id": event_id.hex(),
        "pubkey": pubkey_hex,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": sig.hex(),
    }


class NostrDiscoveryBackend:
    def __init__(
        self,
        relays: list[str],
        vibe: "VibeKeys",
        protocol: int,
        get_presence: Callable[[], bytes | None],
        on_presence: Callable[[bytes, int], None] | None = None,
        on_relay_status: Callable[[str], None] | None = None,
    ) -> None:
        if protocol not in MESSAGE_PROTOCOLS.values():
            raise ValueError("unknown chat protocol")
        self._relays = list(relays)
        self._vibe = vibe
        self._get_presence = get_presence
        self._on_presence = on_presence
        self._on_relay_status = on_relay_status
        # Fresh keypair for this backend; never saved.
        self._priv, pub = generate_keypair()
        self._pub_hex = pub.hex()
        self._protocol = protocol
        self._revision = 0
        self._last_publish = 0.0
        self._force_publish = True  # publish as soon as a relay is ready
        self._running = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._connections: dict[str, Any] = {}
        self._lock = threading.Lock()
        self._update_lock = asyncio.Lock()
        self._wake: asyncio.Event | None = None
        self._need_resub = False
        self.last_ok: dict[str, tuple[bool, str]] = {}

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._force_publish = True
        self._last_publish = 0.0
        self._thread = threading.Thread(target=self._thread_main, name="nostr", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        loop = self._loop
        wake = self._wake
        if loop is not None and loop.is_running():
            try:
                if wake is not None:
                    loop.call_soon_threadsafe(wake.set)
                else:
                    loop.call_soon_threadsafe(loop.stop)
            except RuntimeError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            self._thread = None

    def on_vibe_changed(self, protocol: int) -> None:
        """Retune: resubscribe filter and publish presence at once."""
        if protocol not in MESSAGE_PROTOCOLS.values():
            raise ValueError("unknown chat protocol")
        with self._lock:
            self._protocol = protocol
            self._revision += 1
            self._need_resub = True
            self._force_publish = True
            self._last_publish = 0.0
        self._request_publish()

    def tick(self, now: float) -> None:
        if not self._running:
            return
        with self._lock:
            if not self._connections:
                return
            force = self._force_publish
            last = self._last_publish
        if force or (now - last >= PUBLISH_INTERVAL):
            self._request_publish()

    def _request_publish(self) -> None:
        loop = self._loop
        wake = self._wake
        if loop is not None and loop.is_running() and wake is not None:
            try:
                loop.call_soon_threadsafe(wake.set)
            except RuntimeError:
                pass

    async def _update_relays(self) -> None:
        """Apply a changed subscription before publishing current presence."""
        async with self._update_lock:
            with self._lock:
                need_resub = self._need_resub
                self._need_resub = False
                force = self._force_publish
            if need_resub:
                await self._resubscribe_all()
            if force or time.time() - self._last_publish >= PUBLISH_INTERVAL:
                await self._publish_all()

    def _thread_main(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        self._update_lock = asyncio.Lock()
        self._wake = asyncio.Event()
        try:
            loop.run_until_complete(self._supervisor())
        finally:
            pending = asyncio.all_tasks(loop)
            for t in pending:
                t.cancel()
            if pending:
                try:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                except Exception:
                    pass
            loop.close()
            self._loop = None
            self._wake = None

    async def _supervisor(self) -> None:
        tasks = [asyncio.create_task(self._relay_loop(url)) for url in self._relays]
        assert self._wake is not None
        try:
            while self._running:
                await self._wake.wait()
                self._wake.clear()
                if not self._running:
                    break
                await self._update_relays()
        finally:
            for t in tasks:
                t.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def _resubscribe_all(self) -> None:
        msg = json.dumps(["CLOSE", "r2p"])
        req = self._req_message()
        with self._lock:
            conns = list(self._connections.items())
        for _url, ws in conns:
            try:
                await ws.send(msg)
                await ws.send(req)
            except Exception:
                pass

    @staticmethod
    def _filter_tags(snap: "VibeSnapshot", protocol: int) -> list[str]:
        """Cached last, current, and next vibe slot tags."""
        return list(snap.nostr_tags(protocol))

    def _req_message(self) -> str:
        snap = self._vibe.refresh()
        with self._lock:
            protocol = self._protocol
        filt = {"kinds": [KIND_EPHEMERAL], "#t": self._filter_tags(snap, protocol)}
        return json.dumps(["REQ", "r2p", filt])

    async def _relay_loop(self, url: str) -> None:
        while self._running:
            try:
                async with ws_connect(url, open_timeout=10, close_timeout=2, ping_interval=30) as ws:
                    with self._lock:
                        self._connections[url] = ws
                        need_publish = self._force_publish or self._last_publish <= 0.0
                    await ws.send(self._req_message())
                    # Presence as soon as first (or any new) relay is up.
                    if need_publish:
                        await self._update_relays()
                    async for raw in ws:
                        if not self._running:
                            break
                        await self._handle_message(raw, url)
            except asyncio.CancelledError:
                break
            except Exception:
                if not self._running:
                    break
                await asyncio.sleep(3.0)
            finally:
                with self._lock:
                    self._connections.pop(url, None)

    async def _handle_message(self, raw: str | bytes, url: str = "") -> None:
        try:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="strict")
            msg = json.loads(raw)
        except (json.JSONDecodeError, UnicodeError):
            return
        if not isinstance(msg, list) or len(msg) < 2:
            return
        if msg[0] == "OK":
            self._handle_ok(url, msg)
            return
        if msg[0] == "NOTICE":
            note = msg[1] if isinstance(msg[1], str) else ""
            if self._on_relay_status and note:
                host = url.split("://", 1)[-1].split("/", 1)[0]
                self._on_relay_status(f"nostr notice {host}")
            return
        if msg[0] != "EVENT" or len(msg) < 3:
            return
        event = msg[2]
        if not isinstance(event, dict):
            return
        if event.get("kind") != KIND_EPHEMERAL:
            return
        if event.get("pubkey") == self._pub_hex:
            return
        snap = self._vibe.refresh()
        with self._lock:
            protocol = self._protocol
        allowed = snap.nostr_tags(protocol)
        tags = event.get("tags")
        if not isinstance(tags, list) or not any(
            isinstance(tag, list) and len(tag) >= 2 and tag[0] == "t"
            and isinstance(tag[1], str) and tag[1] in allowed
            for tag in tags
        ):
            return
        if not verify_event(event):
            return
        content = event.get("content")
        if not isinstance(content, str):
            return
        self._handle_content(content, protocol)

    def _handle_ok(self, url: str, msg: list) -> None:
        if len(msg) < 3:
            return
        accepted = bool(msg[2])
        reason = msg[3] if len(msg) > 3 and isinstance(msg[3], str) else ""
        host = url.split("://", 1)[-1].split("/", 1)[0] if url else "relay"
        self.last_ok[url or host] = (accepted, reason)
        if self._on_relay_status:
            if accepted:
                self._on_relay_status(f"nostr ok {host}")
            else:
                self._on_relay_status(f"nostr reject {host}")

    def _handle_content(self, content_b64: str, protocol: int) -> None:
        try:
            ciphertext = base64.b64decode(content_b64, validate=True)
        except (ValueError, binascii.Error):
            return
        for key in self._vibe.candidate_presence_keys():
            plain = endpoint_decrypt(key, ciphertext)
            if plain is None:
                continue
            if decode_presence(plain) is None:
                continue
            if self._on_presence:
                self._on_presence(plain, protocol)
            return

    async def _publish_all(self) -> None:
        presence = self._get_presence()
        if not presence:
            return
        with self._lock:
            conns = list(self._connections.values())
            protocol = self._protocol
            revision = self._revision
        if not conns:
            # Keep force flag so we publish when a relay connects.
            with self._lock:
                self._force_publish = True
            return
        snap = self._vibe.refresh()
        cipher = endpoint_encrypt(snap.presence_current, presence)
        content = base64.b64encode(cipher).decode("ascii")
        tags = [["t", value] for value in snap.nostr_tags(protocol)]
        event = build_event(self._priv, self._pub_hex, KIND_EPHEMERAL, tags, content)
        payload = json.dumps(["EVENT", event])
        sent = False
        for ws in conns:
            try:
                await ws.send(payload)
                sent = True
            except Exception:
                pass
        if sent:
            with self._lock:
                if self._revision == revision:
                    self._last_publish = time.time()
                    self._force_publish = False
