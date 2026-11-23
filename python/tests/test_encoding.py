"""Encoding tables tests."""

from pathlib import Path

from r2p.encoding.glyphs import draw_glyph
from r2p.encoding.tables import codes_to_glyphs, encode_text, load_encodings


def test_encode_round_glyphs():
    root = Path(__file__).resolve().parents[1]
    tables = load_encodings(root / "encodings.json")["default"]
    codes = encode_text(tables, "Aa0!")
    assert len(codes) == 4
    glyphs = codes_to_glyphs(tables, codes)
    assert len(glyphs) == 4
    assert glyphs[0].w == 5
    assert glyphs[0].h == 7


def test_separator_encoded():
    root = Path(__file__).resolve().parents[1]
    tables = load_encodings(root / "encodings.json")["default"]
    codes = encode_text(tables, "X ¦ Y")
    assert len(codes) >= 3


def test_glyph_draw_msb_is_leftmost():
    """Lowercase 'b' has stem on the left (mask top row 16 = bit w-1)."""
    root = Path(__file__).resolve().parents[1]
    tables = load_encodings(root / "encodings.json")["default"]
    glyphs = codes_to_glyphs(tables, encode_text(tables, "b"))
    assert len(glyphs) == 1
    g = glyphs[0]
    assert g.rows[0] == 16
    lit: list[tuple[int, int]] = []

    def pixel_fn(_surf, px, py, _color, _scale):
        lit.append((px, py))

    draw_glyph(None, g, 0, 0, (0, 0, 0), scale=1, pixel_fn=pixel_fn)
    # First lit pixel of top stem row must be at x=0 (left), not x=w-1.
    top = [p for p in lit if p[1] == 0]
    assert top, "expected top-row pixels for 'b' stem"
    assert min(p[0] for p in top) == 0
