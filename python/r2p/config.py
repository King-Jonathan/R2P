"""Load and validate application config."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from r2p.protocol.packet import MESSAGE_PROTOCOLS


DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
]


@dataclass
class Config:
    default_callsign: str = "Booperator"
    frequency: str = "7.074"
    channel_key: str = "liberty"
    udp_port: int = 19302
    visible_lines: int = 20
    encoding: str = "default"
    message_mode: str = "pixel"
    nostr_relays: list[str] = field(default_factory=lambda: list(DEFAULT_RELAYS))
    stun_server: str = "stun.l.google.com:19302"
    discovery_backend: str = "nostr"  # nostr | lan | both
    encodings_path: str = "encodings.json"
    config_path: str = "config.json"


def load_config(path: str | Path = "config.json") -> Config:
    path = Path(path)
    data: dict[str, Any] = {}
    if path.is_file():
        with path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, dict):
            raise ValueError("config root must be an object")
        data = raw

    relays = data.get("nostr_relays", DEFAULT_RELAYS)
    if not isinstance(relays, list) or not all(isinstance(r, str) for r in relays):
        relays = list(DEFAULT_RELAYS)

    backend = str(data.get("discovery_backend", "nostr")).strip().lower()
    if backend not in ("nostr", "lan", "both"):
        backend = "nostr"

    port = int(data.get("udp_port", 19302))
    if not (1 <= port <= 65535):
        port = 19302

    lines = int(data.get("visible_lines", 20))
    if lines < 1:
        lines = 20

    mode = str(data.get("message_mode", "pixel")).strip().lower()
    if mode not in MESSAGE_PROTOCOLS:
        raise ValueError("message_mode must be pixel or spectrogram")

    return Config(
        default_callsign=str(data.get("default_callsign", "Booperator"))[:16],
        frequency=str(data.get("frequency", "7.074")),
        channel_key=str(data.get("channel_key", "liberty")),
        udp_port=port,
        visible_lines=lines,
        encoding=str(data.get("encoding", "default")),
        message_mode=mode,
        nostr_relays=list(relays),
        stun_server=str(data.get("stun_server", "stun.l.google.com:19302")),
        discovery_backend=backend,
        encodings_path=str(data.get("encodings_path", "encodings.json")),
        config_path=str(path),
    )


def save_config(cfg: Config, path: str | Path | None = None) -> None:
    path = Path(path or cfg.config_path)
    payload = {
        "default_callsign": cfg.default_callsign[:16],
        "frequency": cfg.frequency,
        "channel_key": cfg.channel_key,
        "udp_port": cfg.udp_port,
        "visible_lines": cfg.visible_lines,
        "encoding": cfg.encoding,
        "message_mode": cfg.message_mode,
        "nostr_relays": cfg.nostr_relays,
        "stun_server": cfg.stun_server,
        "discovery_backend": cfg.discovery_backend,
    }
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
