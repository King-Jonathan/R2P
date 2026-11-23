"""Pixel glyph draw helpers. Rows are bit masks; bit (w-1) = leftmost pixel."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class Glyph:
    w: int
    h: int
    rows: tuple[int, ...]

    @staticmethod
    def from_dict(data: dict) -> Glyph:
        w = int(data.get("w", 5))
        h = int(data.get("h", 7))
        rows = data.get("rows", [])
        if not isinstance(rows, list):
            rows = []
        row_vals = tuple(int(r) & ((1 << w) - 1) for r in rows[:h])
        # pad height
        if len(row_vals) < h:
            row_vals = row_vals + (0,) * (h - len(row_vals))
        return Glyph(w=w, h=h, rows=row_vals)


_PYGAME = None


def draw_glyph(
    surface,
    glyph: Glyph,
    x: int,
    y: int,
    color: tuple[int, int, int],
    scale: int = 2,
    pixel_fn=None,
) -> int:
    """
    Draw one glyph. Return width advanced (glyph.w * scale + gap).
    Row bits: bit (w-1) is leftmost pixel, bit 0 is rightmost.
    pixel_fn(surface, px, py, color, scale) optional; default uses pygame.draw.rect.
    """
    global _PYGAME
    draw_rect = None
    if pixel_fn is None:
        if _PYGAME is None:
            import pygame

            _PYGAME = pygame
        draw_rect = _PYGAME.draw.rect

    for row_i, mask in enumerate(glyph.rows):
        for col in range(glyph.w):
            # MSB at left so default 5x7 masks (e.g. 'b' stem = 16) read correctly.
            if mask & (1 << (glyph.w - 1 - col)):
                px = x + col * scale
                py = y + row_i * scale
                if pixel_fn is not None:
                    pixel_fn(surface, px, py, color, scale)
                else:
                    draw_rect(surface, color, (px, py, scale, scale))
    return glyph.w * scale + scale  # one scale unit gap


def glyph_advance(glyph: Glyph, scale: int = 2) -> int:
    """Pixel width of one glyph including the trailing gap."""
    return glyph.w * scale + scale


def is_blank_glyph(glyph: Glyph) -> bool:
    """True when all row masks are zero (space in the default set)."""
    return all(r == 0 for r in glyph.rows)


def wrap_glyphs(
    glyphs: Sequence[Glyph],
    max_width: int,
    scale: int = 2,
) -> list[list[Glyph]]:
    """
    Word-wrap a glyph sequence to pixel width max_width.
    Blank glyphs (space) are preferred break points. Overlong words hard-split.
    """
    if max_width <= 0:
        return [list(glyphs)] if glyphs else []

    lines: list[list[Glyph]] = []
    line: list[Glyph] = []
    line_w = 0
    word: list[Glyph] = []
    word_w = 0

    def flush_word() -> None:
        nonlocal line, line_w, word, word_w
        if not word:
            return
        if line and line_w + word_w > max_width:
            lines.append(line)
            line = []
            line_w = 0
        if not line and word_w > max_width:
            for g in word:
                a = glyph_advance(g, scale)
                if line and line_w + a > max_width:
                    lines.append(line)
                    line = []
                    line_w = 0
                line.append(g)
                line_w += a
            word = []
            word_w = 0
            return
        line.extend(word)
        line_w += word_w
        word = []
        word_w = 0

    for g in glyphs:
        a = glyph_advance(g, scale)
        if is_blank_glyph(g):
            flush_word()
            if line and line_w + a > max_width:
                lines.append(line)
                line = []
                line_w = 0
            # Drop leading spaces on a new visual line.
            if line:
                line.append(g)
                line_w += a
        else:
            word.append(g)
            word_w += a
    flush_word()
    if line:
        lines.append(line)
    return lines


def draw_glyph_row(
    surface,
    glyphs: Sequence[Glyph],
    x: int,
    y: int,
    color: tuple[int, int, int],
    scale: int = 2,
    max_width: int | None = None,
) -> None:
    cx = x
    for g in glyphs:
        advance = glyph_advance(g, scale)
        if max_width is not None and cx + advance > x + max_width:
            break
        draw_glyph(surface, g, cx, y, color, scale)
        cx += advance
