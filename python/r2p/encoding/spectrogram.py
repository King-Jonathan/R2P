"""Turn standard-font text into PCM audio, and PCM audio into a spectrogram."""

from __future__ import annotations

import zlib
from dataclasses import dataclass

import numpy as np

HEIGHT = 24
FFT_SIZE = 48
MAX_COLUMNS = 8192
PCM_BYTES_PER_COLUMN = FFT_SIZE * 2
SPECTRAL_GAIN = np.float32(28000 * FFT_SIZE / (2 * HEIGHT))

_SEND_FONT = None


@dataclass(frozen=True)
class Spectrogram:
    """Row-major grayscale intensity, calculated from audio. Contains no text."""

    width: int
    pixels: bytes


def _get_send_font():
    """Load and cache pygame's bundled standard font on the send path only."""
    global _SEND_FONT
    import pygame

    if _SEND_FONT is None or not pygame.font.get_init():
        pygame.font.init()
        _SEND_FONT = pygame.font.Font(pygame.font.get_default_font(), 16)
    return _SEND_FONT


def render_text(text: str) -> np.ndarray:
    """Use pygame's bundled standard font only on the send path."""
    import pygame

    if not text or any(ch in text for ch in "\r\n\x00"):
        raise ValueError("use a single line of text")
    # Check before the font library allocates the text surface.
    if len(text) > MAX_COLUMNS:
        raise ValueError("message is too long for spectrogram mode")
    font = _get_send_font()
    width, height = font.size(text)
    if width + 4 > MAX_COLUMNS or height + 4 > HEIGHT:
        raise ValueError("message is too large for spectrogram mode")
    surface = font.render(text, True, (255, 255, 255), (0, 0, 0))
    width, height = surface.get_size()
    if width + 4 > MAX_COLUMNS or height + 4 > HEIGHT:
        raise ValueError("message is too large for spectrogram mode")
    image = np.zeros((HEIGHT, width + 4), dtype=np.uint8)
    rgb = np.frombuffer(pygame.image.tobytes(surface, "RGB"), dtype=np.uint8)
    image[2 : height + 2, 2 : width + 2] = rgb.reshape(height, width, 3)[:, :, 0]
    return image


def text_to_audio(text: str) -> bytes:
    """One 48-sample frame per image column; high frequencies are at the top.

    Send raw-DEFLATE compressed signed 16-bit little-endian PCM (no zlib
    header/trailer; ChaCha20-Poly1305 authenticates every chunk).
    """
    image = render_text(text)
    width = image.shape[1]
    spectrum = np.zeros((width, FFT_SIZE // 2 + 1), dtype=np.complex64)
    scale = np.float32(SPECTRAL_GAIN / 255.0)
    spectrum[:, 1 : HEIGHT + 1] = image[::-1, :].T.astype(np.float32) * scale
    samples = np.rint(np.fft.irfft(spectrum, n=FFT_SIZE, axis=1)).astype("<i2")
    comp = zlib.compressobj(level=6, wbits=-15)
    return comp.compress(samples.tobytes()) + comp.flush()


def audio_to_spectrogram(payload: bytes) -> Spectrogram | None:
    """Calculate a rectangular-window STFT from the received PCM samples.

    Bound decompression and infer the width before allocating FFT arrays.
    The receive path does not load a font or construct message text.
    """
    decoder = zlib.decompressobj(wbits=-15)
    try:
        raw = decoder.decompress(payload, MAX_COLUMNS * PCM_BYTES_PER_COLUMN + 1)
    except zlib.error:
        return None
    width, remainder = divmod(len(raw), PCM_BYTES_PER_COLUMN)
    if remainder or not 1 <= width <= MAX_COLUMNS:
        return None
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        return None
    frames = np.frombuffer(raw, dtype="<i2").reshape(width, FFT_SIZE).astype(np.float32)
    magnitude = np.abs(np.fft.rfft(frames, axis=1))[:, 1 : HEIGHT + 1]
    inv_scale = np.float32(255.0 / SPECTRAL_GAIN)
    intensity = np.clip(np.rint(magnitude * inv_scale), 0, 255).astype(np.uint8)
    return Spectrogram(width, intensity.T[::-1, :].tobytes())


def wrap_spectrogram(image: Spectrogram, max_width: int) -> list[Spectrogram]:
    """Wrap the spectrum at blank gaps. Split long words when necessary."""
    pixels = np.frombuffer(image.pixels, dtype=np.uint8).reshape(HEIGHT, image.width)
    blank = np.max(pixels, axis=0) == 0
    rows = []
    start = 0
    while start < image.width:
        while start < image.width and blank[start]:
            start += 1
        if start == image.width:
            break
        end = min(image.width, start + max(1, max_width))
        if end < image.width:
            gap = 0
            for col in range(end - 1, start - 1, -1):
                if blank[col]:
                    gap += 1
                else:
                    if gap >= 3:
                        end = col + 1
                        break
                    gap = 0
        rows.append(Spectrogram(end - start, pixels[:, start:end].tobytes()))
        start = end
    return rows
