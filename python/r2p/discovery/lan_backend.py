"""LAN discovery via UDP broadcast (protocol = 1)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from r2p.app_core import AppCore


class LanDiscoveryBackend:
    """Periodic LAN broadcast of encrypted binary presence packets."""

    def __init__(
        self,
        core: "AppCore",
        interval_active: float = 30.0,
    ) -> None:
        self._core = core
        self._interval = interval_active
        self._last_pub = 0.0
        self._running = False

    def start(self) -> None:
        self._running = True
        self._last_pub = 0.0

    def stop(self) -> None:
        self._running = False

    def tick(self, now: float) -> None:
        if not self._running:
            return
        if now - self._last_pub >= self._interval:
            self._core.publish_lan_discovery()
            self._last_pub = now

    def on_vibe_changed(self, protocol: int) -> None:
        # publish soon after vibe rotation
        self._last_pub = 0.0
