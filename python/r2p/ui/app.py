"""Main pygame application loop."""

from __future__ import annotations

import sys
from pathlib import Path

from r2p.app_core import AppCore
from r2p.config import Config, save_config
from r2p.ui.chat_view import ChatView
from r2p.ui.dial_view import FIELD_LABELS, FIELD_NAMES, DialFields, DialView
from r2p.ui.text_wrap import wrap_text
from r2p.ui import encoding_editor


# pygame-ce imports as pygame
import pygame

# Compose bar: line pad, help strip, max share of window height.
_COMPOSE_PAD = 8
_COMPOSE_HELP_H = 16
_COMPOSE_MIN_H = 36
_COMPOSE_MAX_FRAC = 0.40
_REDRAW_EVENTS = tuple(
    ev
    for name in ("VIDEOEXPOSE", "WINDOWEXPOSED", "WINDOWRESTORED", "WINDOWSHOWN")
    if (ev := getattr(pygame, name, None)) is not None
)


class App:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.core = AppCore(cfg)
        self.dial = DialView()
        self.chat = ChatView(scale=2)
        self.compose = ""
        self.screen_mode = "main"  # main | editor
        self.editor_name = ""
        self.fields = DialFields(
            frequency=cfg.frequency,
            channel_key=cfg.channel_key,
            callsign=cfg.default_callsign[:16],
            udp_port=str(cfg.udp_port),
            discovery=cfg.discovery_backend,
            encoding=cfg.encoding,
            message_mode=cfg.message_mode,
            focus=0,
            editing=False,
        )
        # Snapshot of field text when double-click edit began (for Esc cancel).
        self._edit_snapshot: str | None = None
        self._ui_version = 0

    def run(self) -> None:
        pygame.init()
        pygame.display.set_caption("R2P")
        screen = pygame.display.set_mode((960, 540), pygame.RESIZABLE)
        clock = pygame.time.Clock()
        font = pygame.font.SysFont("Consolas", 16)
        small = pygame.font.SysFont("Consolas", 14)

        self.core.start()
        # Bound port may have stepped up if preferred was busy.
        self.fields.udp_port = str(self.core.listen_port)
        running = True
        last_render_key = None
        try:
            while running:
                for event in pygame.event.get():
                    if event.type == pygame.QUIT:
                        running = False
                    elif event.type == pygame.VIDEORESIZE:
                        screen = pygame.display.set_mode(event.size, pygame.RESIZABLE)
                        self._ui_version += 1
                    elif event.type == pygame.MOUSEBUTTONDOWN:
                        self._on_mouse(event)
                        self._ui_version += 1
                    elif event.type == pygame.KEYDOWN:
                        self._on_key(event)
                        self._ui_version += 1
                    elif event.type in _REDRAW_EVENTS:
                        self._ui_version += 1
                render_key = (
                    self._ui_version,
                    self.core.log_version(),
                    self.core.current_status(),
                    self.core.peer_count(),
                    screen.get_size(),
                )
                if render_key != last_render_key:
                    self._draw(screen, font, small)
                    pygame.display.flip()
                    last_render_key = render_key
                clock.tick(30)
        finally:
            self.core.stop()
            save_config(self.cfg)
            pygame.quit()

    def _on_mouse(self, event) -> None:
        if self.screen_mode != "main":
            return
        if event.button != 1:
            return
        idx = self.dial.hit_test(event.pos)
        if idx is None:
            if self.fields.editing:
                self._cancel_dial_edit()
            return
        if event.clicks >= 2:
            self._begin_dial_edit(idx)
            return
        # Single click: focus only; leave edit mode if switching fields.
        if self.fields.editing and idx != self.fields.focus:
            self._cancel_dial_edit()
        self.fields.focus = idx
        if idx in (4, 6) and not self.fields.editing:
            self._toggle_dial(idx)

    def _toggle_dial(self, idx: int) -> None:
        self._cancel_dial_edit()
        self.fields.focus = idx
        if idx == 4:
            nxt = self.core.cycle_discovery_backend()
            self.fields.discovery = nxt
            self.core.status(f"discovery {nxt}")
        elif idx == 6:
            mode = "spectrogram" if self.cfg.message_mode == "pixel" else "pixel"
            self.core.set_message_mode(mode)
            self.fields.message_mode = mode
            self.core.status(f"{mode} mode applied · log and peers cleared · presence published")
        save_config(self.cfg)

    def _begin_dial_edit(self, idx: int) -> None:
        if idx in (4, 6):
            # The first click already applied a toggle.
            return
        self.fields.focus = idx
        self.fields.editing = True
        self._edit_snapshot = self._field_text(idx)
        self.core.status(f"edit {FIELD_LABELS[idx]} (Enter apply, Esc cancel)")

    def _cancel_dial_edit(self) -> None:
        if self.fields.editing and self._edit_snapshot is not None:
            self._set_field_text(self.fields.focus, self._edit_snapshot)
        self.fields.editing = False
        self._edit_snapshot = None

    def _field_text(self, idx: int) -> str:
        return getattr(self.fields, FIELD_NAMES[idx])

    def _set_field_text(self, idx: int, value: str) -> None:
        setattr(self.fields, FIELD_NAMES[idx], value[:16] if idx == 2 else value)

    def _on_key(self, event) -> None:
        if self.screen_mode == "editor":
            self._editor_key(event)
            return

        if event.key == pygame.K_ESCAPE:
            if self.fields.editing:
                self._cancel_dial_edit()
                self.core.status("edit cancelled")
                return
            pygame.event.post(pygame.event.Event(pygame.QUIT))
            return
        if event.key == pygame.K_F2:
            if self.cfg.message_mode == "spectrogram":
                self.core.status("encoding editor is available in pixel mode")
                return
            if self.fields.editing:
                self._cancel_dial_edit()
            self.screen_mode = "editor"
            self.editor_name = ""
            self.core.status("editor: type new encoding name, Enter to clone default, Esc back")
            return
        if event.key == pygame.K_TAB and not self.fields.editing:
            mods = event.mod
            self.fields.focus = (self.fields.focus + (-1 if mods & pygame.KMOD_SHIFT else 1)) % len(FIELD_NAMES)
            return
        if event.key == pygame.K_SPACE and self.fields.focus in (4, 6) and not self.fields.editing:
            if not self.compose:
                self._toggle_dial(self.fields.focus)
                return
        if event.key == pygame.K_RETURN:
            if self.fields.editing:
                self._apply_focus_field()
                self.fields.editing = False
                self._edit_snapshot = None
                return
            if self.compose:
                try:
                    self.core.send_chat(self.compose)
                except ValueError as exc:
                    self.core.status(str(exc))
                    return
                self.compose = ""
                self.core.status(f"sent · peers {self.core.peer_count()}")
            return
        if event.key == pygame.K_BACKSPACE:
            if self.fields.editing:
                self._edit_field_backspace()
            else:
                self.compose = self.compose[:-1]
            return

        ch = event.unicode
        if not ch or ch < " ":
            return
        if self.fields.editing:
            self._edit_field_char(ch)
        else:
            self.compose += ch

    def _apply_focus_field(self) -> None:
        f = self.fields
        if f.focus == 0:
            self.core.set_frequency(f.frequency)
            self.core.status("frequency applied · log cleared · presence published")
        elif f.focus == 1:
            self.core.set_channel_key(f.channel_key)
            self.core.status("channel applied · log cleared · presence published")
        elif f.focus == 2:
            self.core.set_callsign(f.callsign)
            f.callsign = self.core.callsign
            self.core.status("callsign applied")
        elif f.focus == 3:
            try:
                port = int(f.udp_port)
                if 1 <= port <= 65535:
                    bound = self.core.rebind_udp(port)
                    # Config keeps preferred port; dial shows actual listen port.
                    f.udp_port = str(bound)
                    extra = f" (preferred {port} busy)" if bound != port else ""
                    self.core.status(f"port {bound}{extra}")
                else:
                    f.udp_port = str(self.core.listen_port)
                    self.core.status("bad port")
            except ValueError:
                f.udp_port = str(self.core.listen_port)
                self.core.status("bad port")
            except OSError:
                f.udp_port = str(self.core.listen_port)
                self.core.status("port bind failed")
        elif f.focus == 5:
            self.core.set_encoding(f.encoding)
            self.core.status("encoding applied")
        else:
            self.core.status("dial applied")
        save_config(self.cfg)

    def _edit_field_char(self, ch: str) -> None:
        idx = self.fields.focus
        if idx != 3 or ch.isdigit():
            self._set_field_text(idx, self._field_text(idx) + ch)

    def _edit_field_backspace(self) -> None:
        idx = self.fields.focus
        self._set_field_text(idx, self._field_text(idx)[:-1])

    def _editor_key(self, event) -> None:
        if event.key == pygame.K_ESCAPE:
            self.screen_mode = "main"
            self.core.status("main")
            return
        if event.key == pygame.K_RETURN:
            name = self.editor_name.strip()
            if name:
                ok = encoding_editor.clone_encoding(self.cfg.encodings_path, "default", name)
                if ok:
                    self.core.reload_encodings()
                    self.fields.encoding = name
                    self.core.set_encoding(name)
                    save_config(self.cfg)
                    self.core.status(f"encoding '{name}' created")
                else:
                    self.core.status("clone failed (exists or bad name)")
            self.screen_mode = "main"
            return
        if event.key == pygame.K_BACKSPACE:
            self.editor_name = self.editor_name[:-1]
            return
        ch = event.unicode
        if ch and ch.isprintable() and ch not in " \t":
            self.editor_name += ch

    def _compose_prompt(self) -> str:
        if self.screen_mode == "editor":
            return f"New encoding name: {self.editor_name}_"
        if self.fields.editing:
            return f"[{FIELD_LABELS[self.fields.focus]}] {self._field_text(self.fields.focus)}_"
        return f"> {self.compose}_"

    def _draw(self, screen, font, small) -> None:
        w, h = screen.get_size()
        screen.fill((12, 14, 18))
        dial_h = self.dial.height_for_width(w)
        # Word-wrap draft / dial edit / editor prompt; grow compose bar as needed.
        text_w = max(40, w - 16)
        line_h = max(font.get_height(), 16)
        prompt = self._compose_prompt()
        prompt_lines = wrap_text(prompt, text_w, lambda s: font.size(s)[0])
        max_compose = max(_COMPOSE_MIN_H, int(h * _COMPOSE_MAX_FRAC))
        need_h = _COMPOSE_PAD + len(prompt_lines) * line_h + _COMPOSE_HELP_H + 4
        compose_h = min(max(_COMPOSE_MIN_H, need_h), max_compose)
        # If height capped, keep only the last lines that fit.
        max_text_lines = max(1, (compose_h - _COMPOSE_PAD - _COMPOSE_HELP_H - 4) // line_h)
        if len(prompt_lines) > max_text_lines:
            prompt_lines = prompt_lines[-max_text_lines:]

        self.dial.draw(screen, small, self.fields, (0, 0, w, dial_h), self.core.current_status())

        log_rect = (0, dial_h, w, h - dial_h - compose_h)
        pygame.draw.rect(screen, (18, 22, 28), log_rect)
        self.chat.draw(screen, self.core.log_entries(), log_rect)

        # Compose bar.
        cy = h - compose_h
        pygame.draw.rect(screen, (28, 32, 40), (0, cy, w, compose_h))
        pygame.draw.line(screen, (60, 70, 90), (0, cy), (w, cy))
        ty = cy + _COMPOSE_PAD // 2
        for line in prompt_lines:
            img = font.render(line, True, (220, 220, 230))
            screen.blit(img, (8, ty))
            ty += line_h
        help_s = small.render(
            f"peers {self.core.peer_count()} | click DISC/MODE | Enter send/apply | F2 encoding | Esc quit",
            True,
            (100, 110, 130),
        )
        screen.blit(help_s, (8, h - _COMPOSE_HELP_H))


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    config_path = "config.json"
    if argv:
        config_path = argv[0]
    from r2p.config import load_config

    cfg = load_config(config_path)
    # Resolve encodings path relative to the config directory.
    cfg_dir = Path(cfg.config_path).resolve().parent
    enc = Path(cfg.encodings_path)
    if not enc.is_file():
        candidate = cfg_dir / "encodings.json"
        if candidate.is_file():
            cfg.encodings_path = str(candidate)
    app = App(cfg)
    app.run()
    return 0
