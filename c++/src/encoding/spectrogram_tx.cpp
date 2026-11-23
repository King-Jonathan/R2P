#include "encoding/spectrogram_tx.hpp"

#include <SDL.h>
#include <SDL_ttf.h>
#include <cstring>
#include <mutex>
#include <unistd.h>

#include "encoding/spectrogram.hpp"

namespace r2p {

namespace {

std::mutex g_font_mu;
TTF_Font* g_send_font = nullptr;

bool file_exists(const char* path) {
    return path && access(path, R_OK) == 0;
}

TTF_Font* get_send_font() {
    if (!TTF_WasInit()) {
        if (TTF_Init() != 0) return nullptr;
        g_send_font = nullptr;
    }
    if (!g_send_font) {
        std::string path = find_system_font(false);
        if (path.empty()) return nullptr;
        g_send_font = TTF_OpenFont(path.c_str(), 15);
    }
    return g_send_font;
}

}  // namespace

std::string find_system_font(bool monospace) {
    static const char* kMono[] = {
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/ubuntu/UbuntuSansMono[wght].ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/truetype/freefont/FreeMono.ttf",
        nullptr,
    };
    static const char* kSans[] = {
        "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        nullptr,
    };
    const char** list = monospace ? kMono : kSans;
    for (int i = 0; list[i] != nullptr; ++i) {
        if (file_exists(list[i])) return std::string(list[i]);
    }
    return std::string();
}

bool text_to_audio(const std::string& text, std::vector<uint8_t>& out, std::string& error_out) {
    out.clear();
    error_out.clear();
    if (text.empty()) {
        error_out = "use a single line of text";
        return false;
    }
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\r' || text[i] == '\n' || text[i] == '\0') {
            error_out = "use a single line of text";
            return false;
        }
    }
    if (text.size() > static_cast<size_t>(kMaxColumns)) {
        error_out = "message is too long for spectrogram mode";
        return false;
    }

    int img_w = 0;
    std::vector<uint8_t> image;
    {
        std::lock_guard<std::mutex> lock(g_font_mu);
        TTF_Font* font = get_send_font();
        if (!font) {
            error_out = "failed to load standard font";
            return false;
        }
        int tw = 0, th = 0;
        if (TTF_SizeUTF8(font, text.c_str(), &tw, &th) != 0) {
            error_out = "font measurement failed";
            return false;
        }
        if (tw + 4 > kMaxColumns || th + 4 > kSpectrogramHeight) {
            error_out = "message is too large for spectrogram mode";
            return false;
        }
        SDL_Color fg = {255, 255, 255, 255};
        SDL_Color bg = {0, 0, 0, 255};
        SDL_Surface* raw_surf = TTF_RenderUTF8_Shaded(font, text.c_str(), fg, bg);
        if (!raw_surf) {
            error_out = "font render failed";
            return false;
        }
        SDL_Surface* rgb = SDL_ConvertSurfaceFormat(raw_surf, SDL_PIXELFORMAT_RGB24, 0);
        SDL_FreeSurface(raw_surf);
        if (!rgb) {
            error_out = "surface convert failed";
            return false;
        }
        int sw = rgb->w;
        int sh = rgb->h;
        if (sw + 4 > kMaxColumns || sh + 4 > kSpectrogramHeight) {
            SDL_FreeSurface(rgb);
            error_out = "message is too large for spectrogram mode";
            return false;
        }
        img_w = sw + 4;
        image.assign(static_cast<size_t>(kSpectrogramHeight) * static_cast<size_t>(img_w), 0);
        int y_off = (kSpectrogramHeight - sh) / 2;
        if (y_off < 0) y_off = 0;
        const uint8_t* pixels = static_cast<const uint8_t*>(rgb->pixels);
        for (int y = 0; y < sh && y + y_off < kSpectrogramHeight; ++y) {
            const uint8_t* src_row = pixels + y * rgb->pitch;
            uint8_t* dst_row = image.data() + static_cast<size_t>(y + y_off) * static_cast<size_t>(img_w);
            for (int x = 0; x < sw; ++x) {
                dst_row[x + 2] = src_row[x * 3];
            }
        }
        SDL_FreeSurface(rgb);
    }

    std::vector<uint8_t> pcm;
    columns_to_pcm(img_w, image.data(), pcm);
    if (!deflate_raw(pcm.data(), pcm.size(), out)) {
        error_out = "audio compression failed";
        return false;
    }
    return true;
}

void shutdown_send_font() {
    std::lock_guard<std::mutex> lock(g_font_mu);
    if (g_send_font && TTF_WasInit()) {
        TTF_CloseFont(g_send_font);
    }
    g_send_font = nullptr;
}

}  // namespace r2p
