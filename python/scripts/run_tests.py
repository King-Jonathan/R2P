#!/usr/bin/env python3
"""Run R2P unit tests without pytest (project root as cwd)."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULES = [
    "tests.test_vibe",
    "tests.test_packet",
    "tests.test_chunking",
    "tests.test_encoding",
    "tests.test_cipher",
    "tests.test_udp_port",
    "tests.test_wrap",
    "tests.test_presence",
    "tests.test_wsl_nat",
    "tests.test_stun",
    "tests.test_limits",
    "tests.test_bip340",
    "tests.test_nostr_event",
    "tests.test_discovery_toggle",
    "tests.test_spectrogram",
]


def main() -> int:
    sys.path.insert(0, str(ROOT))
    failed = 0
    passed = 0
    for mod_name in MODULES:
        mod = importlib.import_module(mod_name)
        for name in sorted(n for n in dir(mod) if n.startswith("test_")):
            try:
                getattr(mod, name)()
                print("OK", name)
                passed += 1
            except Exception as exc:
                failed += 1
                print("FAIL", name, exc)
    print(f"{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
