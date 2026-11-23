"""Audio spectra, mode isolation, UDP transfer, and mode dial checks."""

from pathlib import Path
from unittest.mock import patch
import json
import subprocess
import sys
import zlib

import numpy as np

from r2p.app_core import AppCore
from r2p.config import Config, load_config
from r2p.encoding.spectrogram import (
    FFT_SIZE, HEIGHT, MAX_COLUMNS,
    PCM_BYTES_PER_COLUMN, SPECTRAL_GAIN, Spectrogram,
    audio_to_spectrogram, render_text, text_to_audio, wrap_spectrogram,
)
from r2p.protocol.chunking import MAX_MESSAGE_BYTES, MessageAssembler, build_message_body, chunk_body
from r2p.protocol.packet import PROTOCOL_SPECTROGRAM, PROTOCOL_PIXEL, unpack_packet

ROOT = Path(__file__).resolve().parents[1]


def _core(mode="pixel", port=40600):
    return AppCore(Config(
        message_mode=mode, udp_port=port, discovery_backend="nostr", nostr_relays=[],
        default_callsign="TestOp", encodings_path=str(ROOT / "encodings.json"),
    ))


def _deflate_raw(raw: bytes) -> bytes:
    comp = zlib.compressobj(level=6, wbits=-15)
    return comp.compress(raw) + comp.flush()


def test_audio_contains_pcm_and_spectrogram_matches_standard_font():
    old_size = new_size = 0
    assert FFT_SIZE == 48
    for message in (
        "Hi", "Meet me on the same channel at 19:30.",
        "The quick brown fox jumps over the lazy dog. 0123456789",
        "Il1 O0 rn m vv w !?.,:; @#% & () / + - =",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz",
        "Caf\u00e9 d\u00e9j\u00e0 vu; ma\u00f1ana. \u00a310 + \u20ac20",
    ):
        text = build_message_body("TestOp", message)
        expected = render_text(text)
        width = expected.shape[1]
        payload = text_to_audio(text)
        raw = zlib.decompress(payload, wbits=-15)
        assert len(raw) == width * PCM_BYTES_PER_COLUMN
        assert _deflate_raw(raw) == payload
        result = audio_to_spectrogram(payload)
        assert result is not None and result.width == width
        assert result.pixels == expected.tobytes()
        # Confirm the 48-sample raw-DEFLATE payload is less than half a 128-sample zlib baseline.
        spectrum = np.zeros((width, 65), dtype=np.complex128)
        spectrum[:, 1:HEIGHT + 1] = expected[::-1, :].T * (28000 * 128 / (2 * HEIGHT * 255))
        old_pcm = np.rint(np.fft.irfft(spectrum, n=128, axis=1)).astype("<i2").tobytes()
        old_size += 8 + len(zlib.compress(old_pcm))
        new_size += len(payload)
    assert new_size < old_size / 2
    assert all(row.width <= 70 for row in wrap_spectrogram(result, 70))
    assert len(wrap_spectrogram(result, 70)) > 1
    # A tone gives a frequency row; silence gives a blank spectrum.
    samples = np.rint(10000 * np.cos(2 * np.pi * 8 * np.arange(FFT_SIZE) / FFT_SIZE)).astype("<i2")
    tone = audio_to_spectrogram(_deflate_raw(samples.tobytes()))
    assert tone is not None
    assert np.argmax(np.frombuffer(tone.pixels, dtype=np.uint8)) == HEIGHT - 8
    silence = audio_to_spectrogram(_deflate_raw(bytes(len(raw))))
    assert silence is not None and not any(silence.pixels)


def test_packets_render_in_separate_process_without_text_or_fonts():
    sender = _core("spectrogram")
    message = "Only the audio crosses this process boundary."
    try:
        sender.peers.add("127.0.0.1", 40601)
        with patch.object(sender._udp, "enqueue_send") as sends:
            sender.send_chat(message)
        packets = [call.args[0] for call in sends.call_args_list]
        chunks = {}
        for raw in packets:
            packet = unpack_packet(raw)
            assert packet is not None and packet.protocol == PROTOCOL_SPECTROGRAM
            chunks[packet.chunk_id] = sender._decrypt_body(packet)
        payload = b"".join(chunks[index] for index in range(len(chunks)))
        decoder = zlib.decompressobj(wbits=-15)
        pcm = decoder.decompress(payload)
        width = len(pcm) // PCM_BYTES_PER_COLUMN
        assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
        assert len(pcm) == width * FFT_SIZE * 2
        assert message.encode("utf-8") not in payload and message.encode("utf-8") not in pcm
        # Check the transmitted samples against the sender's standard-font image.
        frames = np.frombuffer(pcm, dtype="<i2").reshape(width, FFT_SIZE)
        magnitudes = np.abs(np.fft.rfft(frames, axis=1))[:, 1:HEIGHT + 1]
        image = np.clip(np.rint(magnitudes * (255 / SPECTRAL_GAIN)), 0, 255).T[::-1, :]
        expected = render_text(build_message_body(sender.cfg.default_callsign, message))
        assert np.max(np.abs(image.astype(int) - expected.astype(int))) <= 1

        # Only encrypted datagrams enter this process. No message, callsign,
        # sender image, or expected result is supplied to it.
        receiver_code = r'''
import contextlib
import json
import sys
from dataclasses import fields
from unittest.mock import patch
import numpy as np
import pygame
from r2p.app_core import AppCore, LogEntry
from r2p.config import Config
from r2p.encoding.spectrogram import HEIGHT, Spectrogram
from r2p.ui.chat_view import ChatView

packets = json.load(sys.stdin)
core = AppCore(Config(message_mode="spectrogram", default_callsign="",
                      discovery_backend="nostr", nostr_relays=[]))
core._encodings = {}
core._tables = None
try:
    with contextlib.ExitStack() as stack:
        for target in (
            "pygame.font.Font", "pygame.font.SysFont",
            "r2p.encoding.spectrogram.render_text",
            "r2p.encoding.spectrogram.text_to_audio",
            "r2p.app_core.text_to_audio", "r2p.app_core.build_message_body",
            "r2p.app_core.encode_text", "r2p.app_core.codes_to_glyphs",
            "r2p.ui.chat_view.draw_glyph_row", "r2p.ui.chat_view.wrap_glyphs",
            "numpy.fft.irfft",
        ):
            stack.enter_context(patch(target, side_effect=AssertionError(target)))
        stack.enter_context(patch.object(core, "_handle_discovery_body",
                                         side_effect=AssertionError("text decode")))
        fft = stack.enter_context(patch("numpy.fft.rfft", wraps=np.fft.rfft))
        for packet in reversed(packets):
            core._on_udp(bytes.fromhex(packet), ("127.0.0.1", 40601))
        entries = core.log_entries()
        assert len(entries) == 1 and not entries[0].local
        spectrum = entries[0].content
        assert isinstance(spectrum, Spectrogram)
        assert {field.name for field in fields(Spectrogram)} == {"width", "pixels"}
        assert {field.name for field in fields(LogEntry)} == {"content", "received_at", "local"}
        screen = pygame.Surface((spectrum.width + 8, HEIGHT + 4))
        ChatView().draw(screen, entries, (0, 0, screen.get_width(), screen.get_height()))
        assert np.any(pygame.surfarray.array3d(screen))
        assert fft.call_count == 1
        print(json.dumps({"width": spectrum.width, "pixels": spectrum.pixels.hex()}))
finally:
    core.stop()
'''
        result = subprocess.run(
            [sys.executable, "-c", receiver_code], cwd=ROOT,
            input=json.dumps([raw.hex() for raw in packets]),
            capture_output=True, text=True, timeout=20,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        # pygame can print its start message before the JSON result.
        received = json.loads(result.stdout.splitlines()[-1])
        local = sender.log_entries()[0].content
        assert received == {"width": local.width, "pixels": local.pixels.hex()}
    finally:
        sender.stop()


def test_audio_rejects_invalid_and_oversized_data():
    payload = text_to_audio("test")
    invalid = [
        b"", b"bad audio", payload[:-1], payload + b"trailing data",
        payload + payload, b"\x78\x9c" + payload,
    ] + [
        _deflate_raw(raw) for raw in (
            b"", b"short", bytes(PCM_BYTES_PER_COLUMN + 1),
            bytes((MAX_COLUMNS + 1) * PCM_BYTES_PER_COLUMN),
        )
    ]
    with patch("numpy.fft.rfft", side_effect=AssertionError("invalid PCM reached FFT")):
        assert all(audio_to_spectrogram(data) is None for data in invalid)
    limit = audio_to_spectrogram(_deflate_raw(bytes(MAX_COLUMNS * PCM_BYTES_PER_COLUMN)))
    assert limit is not None and limit.width == MAX_COLUMNS
    try:
        text_to_audio("W" * MAX_COLUMNS)
    except ValueError:
        pass
    else:
        raise AssertionError("oversized text must not allocate an audio message")
    try:
        chunk_body(bytes(MAX_MESSAGE_BYTES + 1))
    except ValueError:
        pass
    else:
        raise AssertionError("oversized messages must not be split")
    assembler = MessageAssembler()
    assert assembler.feed(b"msgid!", 65535, b"x" * 200) is None
    assert assembler.pending_count() == 0


def test_modes_filter_before_decryption_and_give_the_same_spectrum():
    a = _core("spectrogram")
    b = _core()
    addr = ("127.0.0.1", 40601)
    try:
        a.peers.add(*addr)
        with patch.object(a._udp, "enqueue_send") as sends:
            a.send_chat("ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz")
        packets = [call.args[0] for call in sends.call_args_list]
        assert max(unpack_packet(raw).chunk_id for raw in packets) > 127
        assert all(unpack_packet(raw).protocol == PROTOCOL_SPECTROGRAM for raw in packets)
        with patch.object(b, "_decrypt_body", side_effect=AssertionError("wrong-mode decrypt")):
            for raw in packets:
                b._on_udp(raw, addr)
        assert b.log_entries() == [] and b.peer_count() == 0
        assert b.dedup.size() == 0 and b.assembler.pending_count() == 0
        b.set_message_mode("spectrogram")
        b._on_udp(packets[0], addr)
        assert b.assembler.pending_count() == 1
        b.set_message_mode("pixel")
        assert b.assembler.pending_count() == 0
        b.set_message_mode("spectrogram")
        # The partial message was discarded. A new send has a new id.
        with patch.object(a._udp, "enqueue_send") as sends:
            a.send_chat("ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz")
        packets = [call.args[0] for call in sends.call_args_list]
        for raw in reversed(packets):
            b._on_udp(raw, addr)
        assert len(b.log_entries()) == 1
        assert b.log_entries()[0].content == a.log_entries()[-1].content
        assert isinstance(b.log_entries()[0].content, Spectrogram)
        assert not b.log_entries()[0].local
        a.set_message_mode("pixel")
        a.peers.add(*addr)
        with patch.object(a._udp, "enqueue_send") as sends:
            a.send_chat("pixel message")
        with patch.object(b, "_decrypt_body", side_effect=AssertionError("wrong-mode decrypt")):
            for call in sends.call_args_list:
                b._on_udp(call.args[0], addr)
        assert len(b.log_entries()) == 1
        # Changing modes removes queued old-mode traffic but keeps discovery.
        a.publish_lan_discovery()
        a.send_chat("queued pixel message")
        assert any(item[2][0] == PROTOCOL_PIXEL for item in a._udp._send_q)
        a.set_message_mode("spectrogram")
        assert a.log_entries() == []
        assert all(item[2][0] != PROTOCOL_PIXEL for item in a._udp._send_q)
        a.peers.add(*addr)
        a.send_chat("queued audio message")
        a.set_frequency("new room")
        assert all(item[2][0] != PROTOCOL_SPECTROGRAM for item in a._udp._send_q)
    finally:
        a.stop()
        b.stop()


def test_spectrogram_udp_roundtrip():
    import time

    a = _core("spectrogram", 40610)
    b = _core("spectrogram", 40611)
    try:
        a._udp.start()
        b._udp.start()
        a.peers.add("127.0.0.1", b.listen_port)
        b.peers.add("127.0.0.1", a.listen_port)
        a.send_chat("Audio travels over UDP; the spectrum shows these letters.")
        deadline = time.monotonic() + 5
        while not b.log_entries() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(b.log_entries()) == 1
        assert a.log_entries()[0].content == b.log_entries()[0].content
        b.send_chat("Reply received.")
        deadline = time.monotonic() + 5
        while len(a.log_entries()) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(a.log_entries()) == 2
        assert a.log_entries()[-1].content == b.log_entries()[-1].content
    finally:
        a.stop()
        b.stop()


def test_mode_dial_config_and_render():
    import tempfile
    import pygame

    from r2p.ui.app import App

    pygame.font.init()
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        config_path = Path(directory) / "config.json"
        encoding_path = Path(directory) / "encodings.json"
        encoding_path.write_bytes((ROOT / "encodings.json").read_bytes())
        app = App(Config(
            discovery_backend="nostr", nostr_relays=[],
            encodings_path=str(encoding_path), config_path=str(config_path),
        ))
        try:
            for idx in (0, 1, 2, 3, 5):
                original = app._field_text(idx)
                app._begin_dial_edit(idx)
                app._set_field_text(idx, "")
                for ch in "12345678901234567":
                    app._edit_field_char(ch)
                typed = "1234567890123456" if idx == 2 else "12345678901234567"
                if idx == 3:
                    app._edit_field_char("x")
                assert app._field_text(idx) == typed
                app._edit_field_backspace()
                assert app._field_text(idx) == typed[:-1]
                app._cancel_dial_edit()
                assert app._field_text(idx) == original and not app.fields.editing
            app._on_key(pygame.event.Event(pygame.KEYDOWN, {"key": pygame.K_F2}))
            app.editor_name = "Clone"
            app._on_key(pygame.event.Event(pygame.KEYDOWN, {"key": pygame.K_RETURN}))
            from r2p.encoding.tables import load_raw
            from r2p.ui.encoding_editor import clone_encoding
            encodings = load_raw(encoding_path)
            assert encodings["Clone"] == encodings["default"]
            assert app.cfg.encoding == load_config(config_path).encoding == "Clone"
            assert not clone_encoding(encoding_path, "default", "Clone")
            screen = pygame.Surface((960, 540))
            font = pygame.font.Font(None, 16)
            app._draw(screen, font, font)
            mode_rect = app.dial._field_rects[6]
            click = pygame.event.Event(pygame.MOUSEBUTTONDOWN, {
                "button": 1, "clicks": 1, "pos": (mode_rect[0] + 10, mode_rect[1] + 10),
            })
            app._on_mouse(click)
            assert app.cfg.message_mode == app.fields.message_mode == "spectrogram"
            assert load_config(config_path).message_mode == "spectrogram"
            app.compose = "W" * MAX_COLUMNS
            app._on_key(pygame.event.Event(pygame.KEYDOWN, {"key": pygame.K_RETURN}))
            assert app.compose == "W" * MAX_COLUMNS and app.core.log_entries() == []
            assert "too" in app.core.current_status()
            app.compose = ""
            app.core.send_chat("Standard font through audio, then a spectrogram.")
            app._draw(screen, font, font)
            assert app.chat._rows and app.chat._rows[0][0].get_height() == HEIGHT
            assert np.any(pygame.surfarray.array3d(screen)[:, 56:500, 1] > 150)
            narrow = pygame.Surface((640, 360))
            app._draw(narrow, font, font)
            assert app.dial._field_rects[6][1] == 34
            assert app.chat._rows and all(row[0].get_width() <= 632 for row in app.chat._rows)
            mode_rect = app.dial._field_rects[6]
            app._on_mouse(pygame.event.Event(pygame.MOUSEBUTTONDOWN, {
                "button": 1, "clicks": 1, "pos": (mode_rect[0] + 10, mode_rect[1] + 10),
            }))
            assert app.cfg.message_mode == "pixel" and app.core.log_entries() == []
            app._draw(screen, font, font)
            assert app.chat._rows == []
        finally:
            app.core.stop()
