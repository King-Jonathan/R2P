#include "encoding/spectrogram.hpp"

#include <cmath>
#include <cstring>
#include <zlib.h>

namespace r2p {

namespace {

struct TrigTables {
    // cos_tab[k][n] = cos(2*pi*(k+1)*n / 48), k in 0..23 (bins 1..24), n in 0..47.
    float cos_tab[kSpectrogramHeight][kFftSize];
    float sin_tab[kSpectrogramHeight][kFftSize];

    TrigTables() {
        const double two_pi_over_n = 2.0 * 3.14159265358979323846 / static_cast<double>(kFftSize);
        for (int k = 0; k < kSpectrogramHeight; ++k) {
            int bin = k + 1;
            for (int n = 0; n < kFftSize; ++n) {
                double ang = two_pi_over_n * static_cast<double>(bin * n);
                cos_tab[k][n] = static_cast<float>(std::cos(ang));
                sin_tab[k][n] = static_cast<float>(std::sin(ang));
            }
        }
    }
};

const TrigTables& trig() {
    static const TrigTables kTables;
    return kTables;
}

bool inflate_raw_bounded(const uint8_t* data, size_t len, size_t max_out, std::vector<uint8_t>& out) {
    out.clear();
    if (!data || len == 0) return false;
    z_stream strm;
    std::memset(&strm, 0, sizeof(strm));
    if (inflateInit2(&strm, -15) != Z_OK) return false;

    strm.next_in = const_cast<Bytef*>(data);
    strm.avail_in = static_cast<uInt>(len);

    uint8_t chunk[16384];
    int ret = Z_OK;
    while (ret == Z_OK) {
        strm.next_out = chunk;
        strm.avail_out = sizeof(chunk);
        ret = inflate(&strm, Z_NO_FLUSH);
        size_t produced = sizeof(chunk) - strm.avail_out;
        if (out.size() + produced > max_out) {
            inflateEnd(&strm);
            out.clear();
            return false;
        }
        if (produced > 0) {
            out.insert(out.end(), chunk, chunk + produced);
        }
    }
    bool ok = (ret == Z_STREAM_END && strm.avail_in == 0);
    inflateEnd(&strm);
    if (!ok) out.clear();
    return ok;
}

}  // namespace

bool deflate_raw(const uint8_t* data, size_t len, std::vector<uint8_t>& out) {
    out.clear();
    z_stream strm;
    std::memset(&strm, 0, sizeof(strm));
    if (deflateInit2(&strm, 6, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return false;
    }
    strm.next_in = const_cast<Bytef*>(data);
    strm.avail_in = static_cast<uInt>(len);
    uint8_t chunk[16384];
    int ret = Z_OK;
    do {
        strm.next_out = chunk;
        strm.avail_out = sizeof(chunk);
        ret = deflate(&strm, Z_FINISH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            deflateEnd(&strm);
            out.clear();
            return false;
        }
        size_t produced = sizeof(chunk) - strm.avail_out;
        if (produced > 0) out.insert(out.end(), chunk, chunk + produced);
    } while (ret != Z_STREAM_END);
    deflateEnd(&strm);
    return true;
}

void columns_to_pcm(int width, const uint8_t* row_major_pixels, std::vector<uint8_t>& pcm_out) {
    const TrigTables& t = trig();
    const float scale = kSpectralGain / 255.0f;
    const float inv_n = 1.0f / static_cast<float>(kFftSize);
    pcm_out.resize(static_cast<size_t>(width) * kPcmBytesPerColumn);

    for (int col = 0; col < width; ++col) {
        float mag[kSpectrogramHeight];
        for (int k = 0; k < kSpectrogramHeight; ++k) {
            // High frequency at top: bin (k+1) comes from row (HEIGHT - 1 - k).
            int row = kSpectrogramHeight - 1 - k;
            mag[k] = static_cast<float>(row_major_pixels[row * width + col]) * scale;
        }
        uint8_t* dst = pcm_out.data() + static_cast<size_t>(col) * kPcmBytesPerColumn;
        for (int n = 0; n < kFftSize; ++n) {
            float sum = 0.0f;
            for (int k = 0; k < kSpectrogramHeight - 1; ++k) {
                sum += 2.0f * mag[k] * t.cos_tab[k][n];
            }
            // Nyquist bin (k = 23 -> bin 24): appears once.
            sum += mag[kSpectrogramHeight - 1] * t.cos_tab[kSpectrogramHeight - 1][n];
            float sample_f = std::nearbyintf(sum * inv_n);
            if (sample_f > 32767.0f) sample_f = 32767.0f;
            if (sample_f < -32768.0f) sample_f = -32768.0f;
            int16_t s = static_cast<int16_t>(sample_f);
            uint16_t u = static_cast<uint16_t>(s);
            dst[n * 2] = static_cast<uint8_t>(u & 0xFF);
            dst[n * 2 + 1] = static_cast<uint8_t>((u >> 8) & 0xFF);
        }
    }
}

bool audio_to_spectrogram(const uint8_t* payload, size_t len, Spectrogram& out) {
    out.width = 0;
    out.pixels.clear();
    std::vector<uint8_t> raw;
    if (!inflate_raw_bounded(payload, len, static_cast<size_t>(kMaxColumns) * kPcmBytesPerColumn, raw)) {
        return false;
    }
    if (raw.empty() || (raw.size() % kPcmBytesPerColumn) != 0) return false;
    int width = static_cast<int>(raw.size() / kPcmBytesPerColumn);
    if (width < 1 || width > kMaxColumns) return false;

    const TrigTables& t = trig();
    const float inv_scale = 255.0f / kSpectralGain;
    out.width = width;
    out.pixels.resize(static_cast<size_t>(kSpectrogramHeight) * static_cast<size_t>(width));

    for (int col = 0; col < width; ++col) {
        const uint8_t* src = raw.data() + static_cast<size_t>(col) * kPcmBytesPerColumn;
        float frame[kFftSize];
        for (int n = 0; n < kFftSize; ++n) {
            uint16_t u = static_cast<uint16_t>(src[n * 2]) |
                         (static_cast<uint16_t>(src[n * 2 + 1]) << 8);
            frame[n] = static_cast<float>(static_cast<int16_t>(u));
        }
        for (int k = 0; k < kSpectrogramHeight; ++k) {
            float re = 0.0f;
            float im = 0.0f;
            for (int n = 0; n < kFftSize; ++n) {
                re += frame[n] * t.cos_tab[k][n];
                im -= frame[n] * t.sin_tab[k][n];
            }
            float mag = std::sqrt(re * re + im * im);
            float val = std::nearbyintf(mag * inv_scale);
            if (val < 0.0f) val = 0.0f;
            if (val > 255.0f) val = 255.0f;
            int row = kSpectrogramHeight - 1 - k;
            out.pixels[static_cast<size_t>(row) * static_cast<size_t>(width) + static_cast<size_t>(col)] =
                static_cast<uint8_t>(val);
        }
    }
    return true;
}

bool audio_to_spectrogram(const std::vector<uint8_t>& payload, Spectrogram& out) {
    return payload.empty() ? false : audio_to_spectrogram(payload.data(), payload.size(), out);
}

std::vector<Spectrogram> wrap_spectrogram(const Spectrogram& image, int max_width) {
    std::vector<Spectrogram> rows;
    if (image.width <= 0 || image.pixels.size() !=
        static_cast<size_t>(kSpectrogramHeight) * static_cast<size_t>(image.width)) {
        return rows;
    }
    int mw = max_width > 1 ? max_width : 1;
    std::vector<uint8_t> blank(static_cast<size_t>(image.width), 1);
    for (int r = 0; r < kSpectrogramHeight; ++r) {
        const uint8_t* row_ptr = image.pixels.data() + static_cast<size_t>(r) * static_cast<size_t>(image.width);
        for (int c = 0; c < image.width; ++c) {
            if (row_ptr[c] != 0) blank[static_cast<size_t>(c)] = 0;
        }
    }

    int start = 0;
    while (start < image.width) {
        while (start < image.width && blank[static_cast<size_t>(start)]) ++start;
        if (start >= image.width) break;
        int end = (start + mw < image.width) ? (start + mw) : image.width;
        if (end < image.width) {
            int gap = 0;
            for (int col = end - 1; col >= start; --col) {
                if (blank[static_cast<size_t>(col)]) {
                    ++gap;
                } else {
                    if (gap >= 3) {
                        end = col + 1;
                        break;
                    }
                    gap = 0;
                }
            }
        }
        int w = end - start;
        Spectrogram slice;
        slice.width = w;
        slice.pixels.resize(static_cast<size_t>(kSpectrogramHeight) * static_cast<size_t>(w));
        for (int r = 0; r < kSpectrogramHeight; ++r) {
            const uint8_t* src = image.pixels.data() +
                                 static_cast<size_t>(r) * static_cast<size_t>(image.width) +
                                 static_cast<size_t>(start);
            uint8_t* dst = slice.pixels.data() + static_cast<size_t>(r) * static_cast<size_t>(w);
            std::memcpy(dst, src, static_cast<size_t>(w));
        }
        rows.push_back(slice);
        start = end;
    }
    return rows;
}

}  // namespace r2p
