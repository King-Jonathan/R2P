"""Word-wrap tests for glyphs and UI text."""

from pathlib import Path

from r2p.encoding.glyphs import Glyph, glyph_advance, wrap_glyphs
from r2p.encoding.tables import codes_to_glyphs, encode_text, load_encodings
from r2p.ui.text_wrap import wrap_text


def _tables():
    root = Path(__file__).resolve().parents[1]
    return load_encodings(root / "encodings.json")["default"]


def test_wrap_glyphs_breaks_on_space():
    tables = _tables()
    glyphs = codes_to_glyphs(tables, encode_text(tables, "aa bb"))
    # Force narrow width: one "aa" fits, full line does not.
    one = codes_to_glyphs(tables, encode_text(tables, "aa"))
    width = sum(glyph_advance(g, 2) for g in one)
    lines = wrap_glyphs(glyphs, max_width=width, scale=2)
    assert len(lines) >= 2
    # First line should be the first word only (spaces dropped at break).
    assert len(lines[0]) == len(one)


def test_wrap_glyphs_hard_splits_long_word():
    g = Glyph(w=5, h=7, rows=(31, 0, 0, 0, 0, 0, 0))
    scale = 2
    adv = glyph_advance(g, scale)
    lines = wrap_glyphs([g, g, g], max_width=adv * 2, scale=scale)
    assert len(lines) == 2
    assert len(lines[0]) == 2
    assert len(lines[1]) == 1


def test_wrap_text_words():
    # measure: 1 unit per character
    lines = wrap_text("hello world", max_width=8, measure=len)
    assert lines == ["hello", "world"]


def test_wrap_text_hard_split():
    lines = wrap_text("abcdefgh", max_width=3, measure=len)
    assert lines == ["abc", "def", "gh"]


def test_wrap_text_empty():
    assert wrap_text("", max_width=10, measure=len) == [""]


def test_send_chat_appends_local_tx_log():
    from r2p.app_core import AppCore
    from r2p.config import Config

    root = Path(__file__).resolve().parents[1]
    cfg = Config(
        discovery_backend="lan",
        encodings_path=str(root / "encodings.json"),
        udp_port=39991,
        default_callsign="TestOp",
    )
    core = AppCore(cfg)
    try:
        core.send_chat("hello")
        entries = core.log_entries()
        assert len(entries) == 1
        assert entries[0].local is True
        assert len(entries[0].content) > 0
    finally:
        core.stop()
