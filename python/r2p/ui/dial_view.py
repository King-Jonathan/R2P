"""Dial strip: frequency, channel, callsign, port, discovery, encoding, and mode."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DialFields:
    frequency: str
    channel_key: str
    callsign: str
    udp_port: str
    discovery: str
    encoding: str
    message_mode: str
    focus: int = 0  # 0..6
    editing: bool = False  # True after double-click; type edits this field


FIELD_NAMES = ("frequency", "channel_key", "callsign", "udp_port", "discovery", "encoding", "message_mode")
FIELD_LABELS = ("FREQ", "CHAN", "CALL", "PORT", "DISC", "ENC", "MODE")


class DialView:
    def __init__(self) -> None:
        self._field_rects: list[tuple[int, int, int, int]] = []

    @staticmethod
    def height_for_width(width: int) -> int:
        return 90 if width < 840 else 56

    def draw(
        self,
        surface,
        font,
        fields: DialFields,
        rect: tuple[int, int, int, int],
        status: str,
    ) -> None:
        import pygame

        x, y, w, h = rect
        pygame.draw.rect(surface, (30, 30, 40), rect)
        pygame.draw.rect(surface, (80, 80, 100), rect, 1)
        labels = [
            f"FREQ {fields.frequency}",
            f"CHAN {fields.channel_key}",
            f"CALL {fields.callsign}",
            f"PORT {fields.udp_port}",
            f"DISC {fields.discovery.upper()}",
            f"ENC {fields.encoding}",
            f"MODE {'SPEC' if fields.message_mode == 'spectrogram' else 'PIXEL'}",
        ]
        columns = 4 if w < 840 else len(labels)
        col_w = max(1, w // columns)
        self._field_rects = []
        for i, label in enumerate(labels):
            fx = x + (i % columns) * col_w
            fy = y + (i // columns) * 34
            fr = (fx, fy, col_w, 34)
            self._field_rects.append(fr)
            if fields.editing and i == fields.focus:
                pygame.draw.rect(surface, (50, 55, 30), fr)
                color = (255, 240, 120)
                text = label[:28] + "_"
            elif i == fields.focus:
                color = (255, 220, 100)
                text = label[:28]
            else:
                color = (200, 200, 210)
                text = label[:28]
            img = font.render(text, True, color)
            previous_clip = surface.get_clip()
            surface.set_clip(fr)
            surface.blit(img, (fx + 6, fy + 8))
            surface.set_clip(previous_clip)
        st = font.render(status[:60], True, (140, 180, 220))
        surface.blit(st, (x + 6, y + h - 22))

    def hit_test(self, pos: tuple[int, int]) -> int | None:
        """Return dial field index under point, or None."""
        px, py = pos
        for i, (fx, fy, fw, fh) in enumerate(self._field_rects):
            if fx <= px < fx + fw and fy <= py < fy + fh:
                return i
        return None
