"""Runtime discovery backend apply."""

from pathlib import Path

from r2p.app_core import AppCore
from r2p.config import Config
from r2p.discovery.lan_backend import LanDiscoveryBackend
from r2p.discovery.nostr_backend import NostrDiscoveryBackend


def test_set_discovery_backend_rebuilds():
    from unittest.mock import patch

    root = Path(__file__).resolve().parents[1]
    cfg = Config(
        discovery_backend="nostr",
        encodings_path=str(root / "encodings.json"),
        udp_port=40400,
        nostr_relays=[],
    )
    core = AppCore(cfg)
    try:
        assert any(isinstance(b, NostrDiscoveryBackend) for b in core._backends)
        assert not any(isinstance(b, LanDiscoveryBackend) for b in core._backends)
        assert core.cycle_discovery_backend() == "both"
        assert core.lan_enabled() and core.nostr_enabled()
        assert any(isinstance(b, LanDiscoveryBackend) for b in core._backends)
        assert any(isinstance(b, NostrDiscoveryBackend) for b in core._backends)
        assert core.cycle_discovery_backend() == "lan"
        assert core.lan_enabled() and not core.nostr_enabled()
        assert not any(isinstance(b, NostrDiscoveryBackend) for b in core._backends)
        with patch.object(core._udp, "enqueue_send") as sends:
            core.send_chat("no broadcast without peers")
        assert sends.call_count == 0
        assert core.cycle_discovery_backend() == "nostr"
        assert core.nostr_enabled() and not core.lan_enabled()
        assert not any(isinstance(b, LanDiscoveryBackend) for b in core._backends)
    finally:
        core.stop()
