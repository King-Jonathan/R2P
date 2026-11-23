"""Wire crypto, protocol, transport, discovery, and message log."""

from __future__ import annotations

import os
import random
import threading
import time
from collections import deque
from dataclasses import dataclass

from r2p.config import Config
from r2p.crypto.cipher import AEAD_TAG_BYTES, body_decrypt, body_encrypt
from r2p.crypto.vibe import VibeKeys
from r2p.discovery.lan_backend import LanDiscoveryBackend
from r2p.discovery.nostr_backend import NostrDiscoveryBackend
from r2p.discovery.peer_list import PeerList
from r2p.discovery.presence import (
    decode_presence,
    encode_presence,
    local_ipv4_addresses,
    pick_send_addr,
    primary_ipv4,
)
from r2p.encoding.glyphs import Glyph
from r2p.encoding.spectrogram import Spectrogram, audio_to_spectrogram, text_to_audio
from r2p.encoding.tables import EncodingTables, codes_to_glyphs, encode_text, load_encodings
from r2p.platform.wsl_nat import WslLanRelay
from r2p.protocol.chunking import (
    MAX_CHUNK_BODY,
    MAX_VALID_CHUNK_ID,
    MessageAssembler,
    build_message_body,
    chunk_body,
)
from r2p.protocol.dedup import DedupCache
from r2p.protocol.packet import (
    MESSAGE_PROTOCOLS,
    PROTOCOL_DISCOVERY,
    PROTOCOL_PIXEL,
    Packet,
    new_message_id,
    pack_header,
    pack_packet,
    packet_aad,
    unpack_packet,
)
from r2p.transport.udp_socket import UdpTransport


@dataclass
class LogEntry:
    """One message as glyphs or a spectrogram, with no message text string."""

    content: list[Glyph] | Spectrogram
    received_at: float
    local: bool = False  # True for own TX echo


class AppCore:
    def __init__(self, cfg: Config) -> None:
        if cfg.message_mode not in MESSAGE_PROTOCOLS:
            raise ValueError("unknown message mode")
        self.cfg = cfg
        self.vibe = VibeKeys(cfg.channel_key, cfg.frequency)
        self.peers = PeerList()
        self.dedup = DedupCache(ttl_seconds=600.0)
        self.assembler = MessageAssembler(max_chunk=MAX_CHUNK_BODY)
        self._encodings = load_encodings(cfg.encodings_path)
        self._tables = self._encodings.get(cfg.encoding) or next(iter(self._encodings.values()))
        self._log: deque[LogEntry] = deque(maxlen=cfg.visible_lines)
        self._log_version = 0
        self._room_epoch = 0
        self._lock = threading.RLock()
        self._status_lock = threading.Lock()
        self._status_box = "boot"
        self._recent_tx_ids: deque[bytes] = deque(maxlen=64)
        self._callsign = cfg.default_callsign[:16]
        self._instance_id = os.urandom(8)
        self._cached_local_ips: list[str] = local_ipv4_addresses()
        self._public_ip: str | None = None
        self._public_port: int | None = None
        self._udp = UdpTransport(cfg.udp_port, on_packet=self._on_udp)
        self._udp.set_error_handler(self.status)
        self._wsl_relay = WslLanRelay()
        self._backends: list[NostrDiscoveryBackend | LanDiscoveryBackend] = []
        self._started = False
        self._stop = threading.Event()
        self._timer_thread: threading.Thread | None = None
        self._last_slot = self.vibe.refresh().slot
        self._net_status = ""
        self._nostr_status = ""
        self._build_backends()

    def _build_backends(self) -> None:
        backends: list[NostrDiscoveryBackend | LanDiscoveryBackend] = []
        backend = self.cfg.discovery_backend
        if backend in ("nostr", "both"):
            backends.append(
                NostrDiscoveryBackend(
                    relays=self.cfg.nostr_relays,
                    vibe=self.vibe,
                    protocol=self.message_protocol,
                    get_presence=self.get_presence_bytes,
                    on_presence=self._on_nostr_presence,
                    on_relay_status=self._on_nostr_status,
                )
            )
        if backend in ("lan", "both"):
            backends.append(LanDiscoveryBackend(self))
        self._backends = backends

    def set_discovery_backend(self, name: str) -> None:
        name = str(name).strip().lower()
        if name not in ("nostr", "lan", "both"):
            return
        if name == self.cfg.discovery_backend:
            return
        old_backends = self._backends
        self._backends = []
        for b in old_backends:
            try:
                b.stop()
            except Exception:
                self.status("backend stop error")
        self.cfg.discovery_backend = name
        if not self.nostr_enabled():
            self._nostr_status = ""
            self._public_ip = None
            self._public_port = None
            self._remember_self_endpoints()
        self._build_backends()
        if self._started:
            for b in self._backends:
                b.start()
            if self.nostr_enabled() and self._public_port is None:
                threading.Thread(target=self._stun_worker, name="stun", daemon=True).start()
            self._notify_vibe()

    def lan_enabled(self) -> bool:
        return self.cfg.discovery_backend in ("lan", "both")

    def nostr_enabled(self) -> bool:
        return self.cfg.discovery_backend in ("nostr", "both")

    def cycle_discovery_backend(self) -> str:
        order = ("nostr", "both", "lan")
        cur = self.cfg.discovery_backend
        nxt = order[(order.index(cur) + 1) % len(order)] if cur in order else "nostr"
        self.set_discovery_backend(nxt)
        return nxt

    def current_status(self) -> str:
        with self._status_lock:
            return self._status_box

    def status(self, msg: str) -> None:
        with self._status_lock:
            self._status_box = msg

    def _on_nostr_status(self, msg: str) -> None:
        self._nostr_status = msg
        self.status(self._combine_status(msg))

    @property
    def tables(self) -> EncodingTables:
        return self._tables

    @property
    def callsign(self) -> str:
        return self._callsign

    def set_callsign(self, value: str) -> None:
        self._callsign = (value or "")[:16]
        self.cfg.default_callsign = self._callsign

    def set_frequency(self, value: str) -> None:
        self.cfg.frequency = value
        self._retune()

    def set_channel_key(self, value: str) -> None:
        self.cfg.channel_key = value
        self._retune()

    def _retune(self) -> None:
        with self._lock:
            self._room_epoch += 1
            self._udp.discard_sends(self.message_protocol)
            self.vibe.set_credentials(self.cfg.channel_key, self.cfg.frequency)
            self.clear_log()
            self.assembler = MessageAssembler(max_chunk=MAX_CHUNK_BODY)
            self.peers.clear()
        self._notify_vibe()

    def clear_log(self) -> None:
        with self._lock:
            self._log.clear()
            self._log_version += 1

    def set_encoding(self, name: str) -> None:
        if name in self._encodings:
            self.cfg.encoding = name
            self._tables = self._encodings[name]

    @property
    def message_protocol(self) -> int:
        return MESSAGE_PROTOCOLS[self.cfg.message_mode]

    def set_message_mode(self, name: str) -> None:
        if name not in MESSAGE_PROTOCOLS:
            raise ValueError("unknown message mode")
        with self._lock:
            if name == self.cfg.message_mode:
                return
            self._room_epoch += 1
            self._udp.discard_sends(self.message_protocol)
            self.cfg.message_mode = name
            self.clear_log()
            self.assembler = MessageAssembler(max_chunk=MAX_CHUNK_BODY)
            self.peers.clear()
        self._notify_vibe()

    def reload_encodings(self) -> None:
        self._encodings = load_encodings(self.cfg.encodings_path)
        self._tables = self._encodings.get(self.cfg.encoding) or next(iter(self._encodings.values()))

    def log_version(self) -> int:
        with self._lock:
            return self._log_version

    def log_entries(self) -> list[LogEntry]:
        with self._lock:
            return list(self._log)

    def peer_count(self) -> int:
        return len(self.peers.all())

    def start(self) -> None:
        self._udp.start()
        self._refresh_local_ips()
        self._public_ip = None
        self._public_port = None
        self._remember_self_endpoints()
        for b in self._backends:
            b.start()
        self._stop.clear()
        self._started = True
        self._wsl_relay.install_hooks()
        self._timer_thread = threading.Thread(target=self._timer_loop, name="core-timer", daemon=True)
        self._timer_thread.start()
        if self.nostr_enabled():
            threading.Thread(target=self._stun_worker, name="stun", daemon=True).start()
        threading.Thread(target=self._wsl_worker, name="wsl-relay", daemon=True).start()
        preferred = self.cfg.udp_port
        bound = self._udp.port
        if bound != preferred:
            self._net_status = f"online :{bound} (preferred {preferred} busy)"
        else:
            self._net_status = f"online :{bound}"
        self.status(self._net_status)

    def stop(self) -> None:
        self._started = False
        self._stop.set()
        for b in self._backends:
            try:
                b.stop()
            except Exception:
                self.status("backend stop error")
        self._wsl_relay.stop()
        self._udp.stop()
        if self._timer_thread:
            self._timer_thread.join(timeout=2.0)
            self._timer_thread = None

    def rebind_udp(self, port: int) -> int:
        self._udp.rebind(port)
        self._wsl_relay.stop()
        self.cfg.udp_port = int(port)
        self._refresh_local_ips()
        self._public_port = None
        self._remember_self_endpoints()
        if self.nostr_enabled():
            threading.Thread(target=self._stun_worker, name="stun", daemon=True).start()
        threading.Thread(target=self._wsl_worker, name="wsl-relay", daemon=True).start()
        self._notify_vibe()
        return self._udp.port

    @property
    def listen_port(self) -> int:
        return self._udp.port

    def _timer_loop(self) -> None:
        while not self._stop.wait(1.0):
            now = time.time()
            snap = self.vibe.refresh(now)
            if snap.slot != self._last_slot:
                self._refresh_local_ips()
                self._remember_self_endpoints()
                self._notify_vibe()
            self.dedup.purge(now)
            self.peers.purge_older_than(3600.0, now)
            with self._lock:
                self.assembler.purge(now)
            self._wsl_relay.beat()
            relay_msg = self._wsl_relay.tick(self._udp.port)
            if relay_msg:
                self._remember_self_endpoints()
                self.status(self._combine_status(relay_msg))
            for b in self._backends:
                try:
                    b.tick(now)
                except Exception:
                    self.status("backend tick error")

    def _stun_worker(self) -> None:
        result = self._udp.stun_query(self.cfg.stun_server)
        if not self.nostr_enabled():
            return
        if result:
            self._public_ip, self._public_port = result
            self._net_status = f"public {self._public_ip}:{self._public_port}"
        else:
            self._public_ip = None
            self._public_port = None
            shown = (self._cached_local_ips[0] if self._cached_local_ips else primary_ipv4()) or "127.0.0.1"
            self._net_status = f"local {shown}:{self._udp.port}"
        self._remember_self_endpoints()
        self.status(self._combine_status(self._nostr_status or self._wsl_relay.status))
        self._notify_vibe()

    def _wsl_worker(self) -> None:
        msg = self._wsl_relay.start(self._udp.port)
        self._remember_self_endpoints()
        if msg:
            self.status(self._combine_status(msg))
            self._notify_vibe()

    def _notify_vibe(self) -> None:
        self._last_slot = self.vibe.refresh().slot
        for b in self._backends:
            try:
                b.on_vibe_changed(self.message_protocol)
            except Exception:
                self.status("vibe notify error")

    def _combine_status(self, extra: str) -> str:
        base = self._net_status
        if extra and base:
            return f"{base} · {extra}"
        return extra or base

    def _refresh_local_ips(self) -> None:
        self._cached_local_ips = local_ipv4_addresses()

    def _local_ips(self) -> set[str]:
        ips = set(self._cached_local_ips)
        if self._wsl_relay.active:
            ips.update(self._wsl_relay.host_lan_ips)
        return ips

    def _advertised_local_ips(self) -> list[str]:
        if self._wsl_relay.active and self._wsl_relay.host_lan_ips:
            return list(self._wsl_relay.host_lan_ips)
        return list(self._cached_local_ips)

    def _our_endpoints(self) -> list[tuple[str, int]]:
        listen = self._udp.port if self._udp.port else self.cfg.udp_port
        pub_port = self._public_port if self._public_port else listen
        out: list[tuple[str, int]] = []
        seen: set[tuple[str, int]] = set()
        if self._public_ip:
            item = (self._public_ip, pub_port)
            out.append(item)
            seen.add(item)
        for ip in self._advertised_local_ips():
            item = (ip, listen)
            if item in seen:
                continue
            out.append(item)
            seen.add(item)
        return out

    def _remember_self_endpoints(self) -> None:
        listen = self._udp.port if self._udp.port else self.cfg.udp_port
        endpoints: set[tuple[str, int]] = {("127.0.0.1", listen)}
        for ip in self._cached_local_ips:
            endpoints.add((ip, listen))
        endpoints.update(self._our_endpoints())
        for ip in self._wsl_relay.host_lan_ips:
            endpoints.add((ip, listen))
        for ip in self._wsl_relay.relay_hosts:
            endpoints.add((ip, listen))
        self.peers.replace_self(endpoints)

    def get_presence_bytes(self) -> bytes | None:
        endpoints = self._our_endpoints()
        if not endpoints:
            listen = self._udp.port if self._udp.port else self.cfg.udp_port
            if self._cached_local_ips:
                endpoints = [(self._cached_local_ips[0], listen)]
        if not endpoints:
            return None
        packed = encode_presence(self._instance_id, endpoints)
        return packed or None

    def _on_nostr_presence(self, raw: bytes, protocol: int) -> None:
        with self._lock:
            if protocol != self.message_protocol:
                return
            addr = self.ingest_presence(raw)
            if addr is not None:
                pkt = self._discovery_packet()
                if pkt is not None:
                    self._send_packet_twice(pkt, peers=[addr])

    def ingest_presence(self, raw: bytes) -> tuple[str, int] | None:
        """Add or refresh binary presence. Return the address only for a new peer."""
        parsed = decode_presence(raw)
        if parsed is None:
            return None
        instance_id, endpoints = parsed
        if instance_id == self._instance_id:
            return None
        listen = self._udp.port
        addr = pick_send_addr(
            their_endpoints=endpoints,
            our_public=self._public_ip,
            our_locals=self._local_ips(),
            our_port=listen,
            our_endpoints=set(self._our_endpoints()) | {("127.0.0.1", listen)},
        )
        if addr is None:
            return None
        if self.peers.add(addr[0], addr[1]):
            return addr
        return None

    def send_chat(self, message: str) -> None:
        with self._lock:
            epoch = self._room_epoch
            callsign = self._callsign
            protocol = self.message_protocol
            tables = self._tables
            room = self.vibe.room_id
            body_key = self.vibe.refresh().body_current
        text = build_message_body(callsign, message)
        if protocol == PROTOCOL_PIXEL:
            encoded = encode_text(tables, text)
            content: list[Glyph] | Spectrogram | None = codes_to_glyphs(tables, encoded)
        else:
            encoded = text_to_audio(text)
            content = audio_to_spectrogram(encoded)
        if not encoded or not content:
            return
        chunks = chunk_body(encoded, MAX_CHUNK_BODY)
        mid = new_message_id()
        packets: list[Packet] = []
        for idx, chunk in enumerate(chunks):
            aad = pack_header(protocol, room, mid, idx, len(chunk) + AEAD_TAG_BYTES)
            cipher = body_encrypt(body_key, mid, idx, chunk, protocol, aad)
            packets.append(
                Packet(
                    protocol=protocol,
                    room_id=room,
                    message_id=mid,
                    chunk_id=idx,
                    body=cipher,
                )
            )
        with self._lock:
            if self._room_epoch != epoch:
                return
            self._append_log(content, local=True)
            self._recent_tx_ids.append(mid)
            peers = self.peers.all()
            if not peers:
                return
            for idx, pkt in enumerate(packets):
                # Pace chunks on the UDP queue so an audio message does not burst.
                self._send_packet_twice(pkt, peers=peers, delay_s=idx * 0.002)

    def publish_lan_discovery(self) -> None:
        pkt = self._discovery_packet()
        if pkt is not None:
            self._send_packet_twice(pkt, peers=self._broadcast_peers())

    def _discovery_packet(self) -> Packet | None:
        plain = self.get_presence_bytes()
        if not plain:
            return None
        mid = new_message_id()
        room = self.vibe.room_id
        body_key = self.vibe.refresh().body_current
        aad = pack_header(PROTOCOL_DISCOVERY, room, mid, 0, len(plain) + AEAD_TAG_BYTES)
        cipher = body_encrypt(body_key, mid, 0, plain, PROTOCOL_DISCOVERY, aad)
        return Packet(
            protocol=PROTOCOL_DISCOVERY,
            room_id=room,
            message_id=mid,
            chunk_id=0,
            body=cipher,
        )

    def _send_packet_twice(
        self, pkt: Packet, peers: list[tuple[str, int]] | None = None, delay_s: float = 0.0,
    ) -> None:
        if peers is None:
            peers = self.peers.all()
        if not peers:
            return
        copy_a = pack_packet(pkt)
        copy_b = pack_packet(pkt)
        delay = delay_s + random.uniform(0.005, 0.020)
        for host, port in peers:
            self._udp.enqueue_send(copy_a, (host, port), delay_s)
            self._udp.enqueue_send(copy_b, (host, port), delay)

    def _broadcast_peers(self) -> list[tuple[str, int]]:
        return [("255.255.255.255", port) for port in self._udp.broadcast_ports()]

    def _on_udp(self, data: bytes, addr: tuple[str, int]) -> None:
        pkt = unpack_packet(data)
        if pkt is None or pkt.chunk_id > MAX_VALID_CHUNK_ID:
            return
        with self._lock:
            epoch = self._room_epoch
            if pkt.room_id != self.vibe.room_id:
                return
            if pkt.protocol not in (PROTOCOL_DISCOVERY, self.message_protocol):
                return
        plain = self._decrypt_body(pkt)
        if plain is None:
            return
        complete: bytes | None = None
        with self._lock:
            if self._room_epoch != epoch:
                return
            if self.dedup.is_duplicate(pkt.message_id, pkt.chunk_id):
                return
            if pkt.protocol == PROTOCOL_DISCOVERY:
                self._handle_discovery_body(plain, addr)
                return
            if pkt.message_id in self._recent_tx_ids:
                return
            complete = self.assembler.feed(pkt.message_id, pkt.chunk_id, plain)
            tables = self._tables
        content: list[Glyph] | Spectrogram | None = None
        if complete is not None:
            if pkt.protocol == PROTOCOL_PIXEL:
                content = codes_to_glyphs(tables, complete)
            else:
                content = audio_to_spectrogram(complete)
        with self._lock:
            if self._room_epoch != epoch:
                return
            if content:
                self._append_log(content, local=False)
            if not self._wsl_relay.is_relay_host(addr[0]) and not self.peers.is_self(addr[0], addr[1]):
                self.peers.add(addr[0], addr[1])

    def _decrypt_body(self, pkt: Packet) -> bytes | None:
        aad = packet_aad(pkt)
        for key in self.vibe.candidate_body_keys():
            plain = body_decrypt(key, pkt.message_id, pkt.chunk_id, pkt.body, pkt.protocol, aad)
            if plain is not None:
                return plain
        return None

    def _handle_discovery_body(self, plain: bytes, addr: tuple[str, int]) -> None:
        parsed = decode_presence(plain)
        if parsed is None:
            return
        instance_id, _endpoints = parsed
        if instance_id == self._instance_id:
            return
        if not self._wsl_relay.is_relay_host(addr[0]):
            ret = (
                ("127.0.0.1", addr[1])
                if addr[0] in self._local_ips() and addr[1] != self._udp.port
                else addr
            )
            if not self.peers.is_self(ret[0], ret[1]):
                self.peers.add(ret[0], ret[1])
                return
        self.ingest_presence(plain)

    def _append_log(self, content: list[Glyph] | Spectrogram, local: bool) -> None:
        if not content:
            return
        entry = LogEntry(content=content, received_at=time.time(), local=local)
        self._log.append(entry)
        self._log_version += 1
