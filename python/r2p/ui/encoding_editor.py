"""Minimal in-app encoding set manager: clone default under a new name."""

from __future__ import annotations

from pathlib import Path

from r2p.encoding.tables import load_raw, save_encodings


def clone_encoding(path: str | Path, source: str, new_name: str) -> bool:
    data = load_raw(path)
    if source not in data or not new_name or new_name in data:
        return False
    data[new_name] = data[source]
    save_encodings(path, data)
    return True
