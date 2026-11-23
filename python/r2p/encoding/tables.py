"""Load encodings.json; map characters to codes and codes to glyph lists."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from r2p.encoding.glyphs import Glyph


@dataclass
class EncodingTables:
    name: str
    char_to_code: dict[str, int]
    code_to_glyphs: dict[int, list[Glyph]]

    def encode_char(self, ch: str) -> int | None:
        if ch in self.char_to_code:
            return self.char_to_code[ch]
        # also try "space" alias for space character
        if ch == " " and "space" in self.char_to_code:
            return self.char_to_code["space"]
        return None


def encode_text(tables: EncodingTables, text: str) -> bytes:
    """Encode text to code bytes. Skip unknown characters."""
    out = bytearray()
    for ch in text:
        code = tables.encode_char(ch)
        if code is not None and 0 <= code <= 255:
            out.append(code & 0xFF)
    return bytes(out)


def codes_to_glyphs(tables: EncodingTables, codes: bytes) -> list[Glyph]:
    """Map code bytes to glyph list. Never builds a text string."""
    glyphs: list[Glyph] = []
    for code in codes:
        glyphs.extend(tables.code_to_glyphs.get(code, ()))
    return glyphs


def _parse_glyph_list(raw: Any) -> list[Glyph]:
    if raw is None:
        return []
    if isinstance(raw, dict):
        return [Glyph.from_dict(raw)]
    if isinstance(raw, list):
        # Read glyph dictionaries; ignore other list items.
        out: list[Glyph] = []
        for item in raw:
            if isinstance(item, dict) and ("rows" in item or "w" in item):
                out.append(Glyph.from_dict(item))
        return out
    return []


def load_encodings(path: str | Path) -> dict[str, EncodingTables]:
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        root = json.load(fh)
    if not isinstance(root, dict):
        raise ValueError("encodings root must be an object")

    result: dict[str, EncodingTables] = {}
    for name, block in root.items():
        if not isinstance(block, dict):
            continue
        enc = block.get("encoding", {})
        dec = block.get("decoding", {})
        char_to_code: dict[str, int] = {}
        if isinstance(enc, dict):
            for k, v in enc.items():
                try:
                    char_to_code[str(k)] = int(v)
                except (TypeError, ValueError):
                    continue
        code_to_glyphs: dict[int, list[Glyph]] = {}
        if isinstance(dec, dict):
            for k, v in dec.items():
                try:
                    code = int(k)
                except (TypeError, ValueError):
                    # skip non-numeric keys like "space" alias if not int
                    if k == "space" and "space" in char_to_code:
                        code = char_to_code["space"]
                    else:
                        continue
                glyphs = _parse_glyph_list(v)
                if glyphs:
                    code_to_glyphs[code] = glyphs
        result[str(name)] = EncodingTables(
            name=str(name),
            char_to_code=char_to_code,
            code_to_glyphs=code_to_glyphs,
        )
    return result


def save_encodings(path: str | Path, data: dict[str, Any]) -> None:
    path = Path(path)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def load_raw(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)
