"""Message log with cached glyph rows or audio spectrogram rows."""

from __future__ import annotations

import numpy as np

from r2p.app_core import LogEntry
from r2p.encoding.glyphs import draw_glyph_row, glyph_advance, wrap_glyphs
from r2p.encoding.spectrogram import HEIGHT, Spectrogram, wrap_spectrogram

# RX = peer traffic; TX = own sent echo (radio-style).
COLOR_RX = (180, 255, 180)
COLOR_TX = (160, 200, 255)


class ChatView:
    def __init__(self, scale: int = 2) -> None:
        self.scale = scale
        self.line_gap = 4
        self._layout_key = None
        self._entries: list[LogEntry] = []
        self._rows: list[tuple[object, int]] = []

    def row_height(self) -> int:
        return 7 * self.scale + self.line_gap

    def draw(
        self,
        surface,
        entries: list[LogEntry],
        rect: tuple[int, int, int, int],
        color: tuple[int, int, int] | None = None,
    ) -> None:
        x, y, w, h = rect
        rh = self.row_height()
        glyph_h = 7 * self.scale
        max_w = max(1, w - 8)
        key = (tuple(id(entry) for entry in entries), max_w, color, self.scale)
        if key != self._layout_key:
            import pygame

            self._rows = []
            # Keep entries alive while their ids are used as cache keys.
            self._entries = list(entries)
            for entry in entries:
                row_color = color if color is not None else (COLOR_TX if entry.local else COLOR_RX)
                if isinstance(entry.content, Spectrogram):
                    for row in wrap_spectrogram(entry.content, max_w):
                        intensity = np.frombuffer(row.pixels, dtype=np.uint8).reshape(HEIGHT, row.width, 1)
                        rgb = (intensity.astype(np.uint16) * np.array(row_color) // 255).astype(np.uint8)
                        image = pygame.image.frombytes(rgb.tobytes(), (row.width, HEIGHT), "RGB")
                        image.set_colorkey((0, 0, 0))
                        self._rows.append((image, HEIGHT + self.line_gap))
                else:
                    for row in wrap_glyphs(entry.content, max_w, self.scale):
                        row_w = min(max_w, max(1, sum(glyph_advance(g, self.scale) for g in row)))
                        image = pygame.Surface((row_w, glyph_h))
                        image.set_colorkey((0, 0, 0))
                        draw_glyph_row(image, row, 0, 0, row_color, self.scale, max_width=row_w)
                        self._rows.append((image, rh))
            self._layout_key = key
        visible = []
        used_h = 0
        for row_img, row_h in reversed(self._rows):
            if used_h + row_h > h:
                break
            visible.append((row_img, row_h))
            used_h += row_h
        cy = y + h - used_h
        for row_img, row_h in reversed(visible):
            surface.blit(row_img, (x + 4, cy))
            cy += row_h
