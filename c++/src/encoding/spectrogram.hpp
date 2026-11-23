#ifndef R2P_ENCODING_SPECTROGRAM_HPP
#define R2P_ENCODING_SPECTROGRAM_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

namespace r2p {

static const int kSpectrogramHeight = 24;
static const int kFftSize = 48;
static const int kMaxColumns = 8192;
static const size_t kPcmBytesPerColumn = static_cast<size_t>(kFftSize * 2);
static const float kSpectralGain = 28000.0f;

// Row-major grayscale intensity (kSpectrogramHeight x width), computed from audio. Contains no text.
struct Spectrogram {
    int width;
    std::vector<uint8_t> pixels;

    Spectrogram() : width(0) {}
    bool operator==(const Spectrogram& o) const {
        return width == o.width && pixels == o.pixels;
    }
};

// Receive path: raw DEFLATE decompress + 48-point float32 STFT (no fonts, no text).
bool audio_to_spectrogram(const uint8_t* payload, size_t len, Spectrogram& out);
bool audio_to_spectrogram(const std::vector<uint8_t>& payload, Spectrogram& out);

// Wrap spectrogram at blank column gaps (>= 3 blank columns).
std::vector<Spectrogram> wrap_spectrogram(const Spectrogram& image, int max_width);

// Shared raw-DEFLATE helper (wbits=-15, level 6) used by spectrogram_tx and tests.
bool deflate_raw(const uint8_t* data, size_t len, std::vector<uint8_t>& out);

// Shared 48-point float32 real IFFT (matches numpy.fft.irfft normalization /48).
void columns_to_pcm(int width, const uint8_t* row_major_pixels, std::vector<uint8_t>& pcm_out);

}  // namespace r2p

#endif
