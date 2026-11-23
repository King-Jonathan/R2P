#include "ui/app.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "encoding/spectrogram_tx.hpp"
#include "encoding/tables.hpp"
#include "protocol/chunking.hpp"
#include "ui/text_wrap.hpp"

namespace r2p {

namespace {

static const char* kFieldLabels[7] = {"FREQ", "CHAN", "CALL", "PORT", "DISC", "ENC", "MODE"};
static const int kGlyphScale = 2;
static const int kLineGap = 5;
static const int kMsgGap = 4;

// Modern HAM-radio dark-slate palette.
static const SDL_Color kBgOuter = {14, 17, 23, 255};
static const SDL_Color kBgHeader = {22, 27, 36, 255};
static const SDL_Color kBgTile = {30, 36, 48, 255};
static const SDL_Color kBgTileFocus = {38, 45, 58, 255};
static const SDL_Color kBgTileEdit = {48, 52, 26, 255};
static const SDL_Color kBgLog = {17, 21, 29, 255};
static const SDL_Color kBgCompose = {24, 30, 41, 255};
static const SDL_Color kBorderDim = {54, 64, 82, 255};
static const SDL_Color kBorderFocus = {240, 184, 90, 255};
static const SDL_Color kTextMain = {220, 226, 236, 255};
static const SDL_Color kTextMuted = {132, 146, 168, 255};
static const SDL_Color kTextLabel = {120, 166, 214, 255};
static const SDL_Color kTextEdit = {255, 242, 156, 255};
static const SDL_Color kAccentPixel = {106, 230, 156, 255};
static const SDL_Color kAccentSpec = {95, 211, 243, 255};
static const SDL_Color kAccentTx = {158, 200, 255, 255};
static const SDL_Color kAccentRx = {168, 255, 168, 255};
static const SDL_Color kRailTx = {84, 148, 235, 255};
static const SDL_Color kRailRx = {92, 218, 134, 255};

void set_color(SDL_Renderer* ren, SDL_Color c) {
    SDL_SetRenderDrawColor(ren, c.r, c.g, c.b, c.a);
}

std::string to_upper(const std::string& s) {
    std::string out = s;
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(out[i])));
    }
    return out;
}

}  // namespace

UiApp::UiApp(const Config& cfg)
    : cfg_(cfg),
      core_(cfg),
      f_freq_(cfg.frequency),
      f_chan_(cfg.channel_key),
      f_call_(truncate_utf8_chars(cfg.default_callsign, 16)),
      f_port_(std::to_string(cfg.udp_port)),
      f_disc_(cfg.discovery_backend),
      f_enc_(cfg.encoding),
      f_mode_(cfg.message_mode),
      focus_(0),
      editing_(false),
      editor_mode_(false),
      ui_version_(1),
      font_main_(nullptr),
      font_small_(nullptr),
      cached_log_version_(0xFFFFFFFFFFFFFFFFULL),
      cached_max_w_(0) {
    SDL_Rect zero = {0, 0, 0, 0};
    field_rects_.fill(zero);
}

UiApp::~UiApp() {
    clear_row_cache();
    if (font_main_) TTF_CloseFont(font_main_);
    if (font_small_) TTF_CloseFont(font_small_);
}

void UiApp::clear_row_cache() {
    for (size_t i = 0; i < cached_rows_.size(); ++i) {
        if (cached_rows_[i].tex) SDL_DestroyTexture(cached_rows_[i].tex);
    }
    cached_rows_.clear();
}

int UiApp::measure_text(TTF_Font* font, const std::string& text) const {
    if (!font || text.empty()) return 0;
    int w = 0, h = 0;
    if (TTF_SizeUTF8(font, text.c_str(), &w, &h) != 0) return 0;
    return w;
}

void UiApp::draw_text(SDL_Renderer* ren, TTF_Font* font, const std::string& text,
                      int x, int y, SDL_Color color, const SDL_Rect* clip) {
    if (!font || text.empty()) return;
    SDL_Surface* surf = TTF_RenderUTF8_Blended(font, text.c_str(), color);
    if (!surf) return;
    SDL_Texture* tex = SDL_CreateTextureFromSurface(ren, surf);
    if (tex) {
        SDL_Rect dst = {x, y, surf->w, surf->h};
        if (clip) SDL_RenderSetClipRect(ren, clip);
        SDL_RenderCopy(ren, tex, nullptr, &dst);
        if (clip) SDL_RenderSetClipRect(ren, nullptr);
        SDL_DestroyTexture(tex);
    }
    SDL_FreeSurface(surf);
}

SDL_Texture* UiApp::make_glyph_row_texture(SDL_Renderer* ren,
                                           const std::vector<Glyph>& row,
                                           SDL_Color color,
                                           int scale,
                                           int max_w,
                                           int& out_w,
                                           int& out_h) {
    int total_w = 0;
    for (size_t i = 0; i < row.size(); ++i) total_w += glyph_advance(row[i], scale);
    out_w = std::max(1, std::min(total_w, max_w));
    out_h = 7 * scale;

    std::vector<uint8_t> rgba(static_cast<size_t>(out_w) * static_cast<size_t>(out_h) * 4, 0);
    int cx = 0;
    for (size_t gi = 0; gi < row.size(); ++gi) {
        const Glyph& g = row[gi];
        int adv = glyph_advance(g, scale);
        if (cx + adv > out_w && cx > 0) break;
        for (int r = 0; r < g.h && r * scale < out_h; ++r) {
            uint32_t mask = g.rows[static_cast<size_t>(r)];
            for (int c = 0; c < g.w; ++c) {
                if ((mask & (1u << (g.w - 1 - c))) != 0) {
                    for (int sy = 0; sy < scale; ++sy) {
                        int py = r * scale + sy;
                        if (py >= out_h) break;
                        for (int sx = 0; sx < scale; ++sx) {
                            int px = cx + c * scale + sx;
                            if (px >= out_w) break;
                            size_t off = (static_cast<size_t>(py) * static_cast<size_t>(out_w) +
                                          static_cast<size_t>(px)) * 4;
                            rgba[off] = color.r;
                            rgba[off + 1] = color.g;
                            rgba[off + 2] = color.b;
                            rgba[off + 3] = 255;
                        }
                    }
                }
            }
        }
        cx += adv;
    }

    SDL_Texture* tex = SDL_CreateTexture(ren, SDL_PIXELFORMAT_ABGR8888,
                                         SDL_TEXTUREACCESS_STATIC, out_w, out_h);
    if (!tex) return nullptr;
    SDL_SetTextureBlendMode(tex, SDL_BLENDMODE_BLEND);
    SDL_UpdateTexture(tex, nullptr, rgba.data(), out_w * 4);
    return tex;
}

SDL_Texture* UiApp::make_spectrogram_row_texture(SDL_Renderer* ren,
                                                 const Spectrogram& row,
                                                 SDL_Color color) {
    if (row.width <= 0) return nullptr;
    int w = row.width;
    int h = kSpectrogramHeight;
    std::vector<uint8_t> rgba(static_cast<size_t>(w) * static_cast<size_t>(h) * 4, 0);
    for (int i = 0; i < w * h; ++i) {
        uint8_t v = row.pixels[static_cast<size_t>(i)];
        if (v == 0) continue;
        size_t off = static_cast<size_t>(i) * 4;
        rgba[off] = static_cast<uint8_t>((static_cast<uint16_t>(v) * color.r) / 255);
        rgba[off + 1] = static_cast<uint8_t>((static_cast<uint16_t>(v) * color.g) / 255);
        rgba[off + 2] = static_cast<uint8_t>((static_cast<uint16_t>(v) * color.b) / 255);
        rgba[off + 3] = 255;
    }
    SDL_Texture* tex = SDL_CreateTexture(ren, SDL_PIXELFORMAT_ABGR8888,
                                         SDL_TEXTUREACCESS_STATIC, w, h);
    if (!tex) return nullptr;
    SDL_SetTextureBlendMode(tex, SDL_BLENDMODE_BLEND);
    SDL_UpdateTexture(tex, nullptr, rgba.data(), w * 4);
    return tex;
}

void UiApp::rebuild_row_cache(SDL_Renderer* ren, const std::vector<LogEntry>& entries, int max_w) {
    clear_row_cache();
    for (size_t i = 0; i < entries.size(); ++i) {
        const LogEntry& e = entries[i];
        SDL_Color col = e.local ? kAccentTx : kAccentRx;
        bool first = true;
        if (e.is_spectrogram) {
            std::vector<Spectrogram> rows = wrap_spectrogram(e.spectrogram, max_w);
            for (size_t r = 0; r < rows.size(); ++r) {
                CachedRow cr;
                cr.tex = make_spectrogram_row_texture(ren, rows[r], col);
                cr.w = rows[r].width;
                cr.h = kSpectrogramHeight;
                cr.row_h = kSpectrogramHeight + kLineGap + (first && i > 0 ? kMsgGap : 0);
                cr.local = e.local;
                cr.is_first_of_msg = first;
                cached_rows_.push_back(cr);
                first = false;
            }
        } else {
            std::vector<std::vector<Glyph> > rows = wrap_glyphs(e.glyphs, max_w, kGlyphScale);
            for (size_t r = 0; r < rows.size(); ++r) {
                CachedRow cr;
                cr.tex = make_glyph_row_texture(ren, rows[r], col, kGlyphScale, max_w, cr.w, cr.h);
                cr.row_h = cr.h + kLineGap + (first && i > 0 ? kMsgGap : 0);
                cr.local = e.local;
                cr.is_first_of_msg = first;
                cached_rows_.push_back(cr);
                first = false;
            }
        }
    }
}

int UiApp::hit_test_dial(int px, int py) const {
    for (int i = 0; i < 7; ++i) {
        const SDL_Rect& r = field_rects_[static_cast<size_t>(i)];
        if (px >= r.x && px < r.x + r.w && py >= r.y && py < r.y + r.h) return i;
    }
    return -1;
}

std::string& UiApp::editable_field_ref(int idx) {
    switch (idx) {
        case 0: return f_freq_;
        case 1: return f_chan_;
        case 2: return f_call_;
        case 3: return f_port_;
        default: return f_enc_;
    }
}

void UiApp::toggle_dial(int idx) {
    cancel_dial_edit();
    focus_ = idx;
    if (idx == 4) {
        f_disc_ = core_.cycle_discovery_backend();
        core_.status("discovery " + f_disc_);
    } else if (idx == 6) {
        std::string next_mode = (f_mode_ == "pixel") ? "spectrogram" : "pixel";
        core_.set_message_mode(next_mode);
        f_mode_ = next_mode;
        core_.status(next_mode + " mode applied | log and peers cleared | presence published");
    }
    cfg_ = core_.config_snapshot();
    save_config(cfg_);
}

void UiApp::begin_dial_edit(int idx) {
    if (idx == 4 || idx == 6) return;
    focus_ = idx;
    editing_ = true;
    edit_snapshot_ = editable_field_ref(idx);
    core_.status(std::string("edit ") + kFieldLabels[idx] + " (Enter apply, Esc cancel)");
}

void UiApp::cancel_dial_edit() {
    if (editing_) {
        editable_field_ref(focus_) = edit_snapshot_;
    }
    editing_ = false;
    edit_snapshot_.clear();
}

void UiApp::apply_focus_field() {
    if (focus_ == 0) {
        core_.set_frequency(f_freq_);
        core_.status("frequency applied | log cleared | presence published");
    } else if (focus_ == 1) {
        core_.set_channel_key(f_chan_);
        core_.status("channel applied | log cleared | presence published");
    } else if (focus_ == 2) {
        core_.set_callsign(f_call_);
        f_call_ = core_.callsign();
        core_.status("callsign applied");
    } else if (focus_ == 3) {
        char* endp = nullptr;
        long p = std::strtol(f_port_.c_str(), &endp, 10);
        if (endp != f_port_.c_str() && *endp == '\0' && p >= 1 && p <= 65535) {
            uint16_t bound = 0;
            if (core_.rebind_udp(static_cast<uint16_t>(p), bound)) {
                f_port_ = std::to_string(bound);
                std::string extra = (bound != p) ? (" (preferred " + std::to_string(p) + " busy)") : "";
                core_.status("port " + std::to_string(bound) + extra);
            } else {
                f_port_ = std::to_string(core_.listen_port());
                core_.status("port bind failed");
            }
        } else {
            f_port_ = std::to_string(core_.listen_port());
            core_.status("bad port");
        }
    } else if (focus_ == 5) {
        if (core_.set_encoding(f_enc_)) {
            core_.status("encoding applied");
        } else {
            f_enc_ = core_.config_snapshot().encoding;
            core_.status("unknown encoding");
        }
    }
    cfg_ = core_.config_snapshot();
    save_config(cfg_);
}

void UiApp::on_mouse(const SDL_MouseButtonEvent& ev) {
    if (editor_mode_ || ev.button != SDL_BUTTON_LEFT) return;
    int idx = hit_test_dial(ev.x, ev.y);
    if (idx < 0) {
        if (editing_) cancel_dial_edit();
        return;
    }
    if (ev.clicks >= 2) {
        begin_dial_edit(idx);
        return;
    }
    if (editing_ && idx != focus_) cancel_dial_edit();
    focus_ = idx;
    if ((idx == 4 || idx == 6) && !editing_) {
        toggle_dial(idx);
    }
}

void UiApp::on_editor_key(const SDL_KeyboardEvent& ev) {
    SDL_Keycode key = ev.keysym.sym;
    if (key == SDLK_ESCAPE) {
        editor_mode_ = false;
        core_.status("main");
        return;
    }
    if (key == SDLK_RETURN || key == SDLK_KP_ENTER) {
        if (!editor_name_.empty()) {
            if (clone_encoding(cfg_.encodings_path, "default", editor_name_)) {
                core_.reload_encodings();
                f_enc_ = editor_name_;
                core_.set_encoding(editor_name_);
                cfg_ = core_.config_snapshot();
                save_config(cfg_);
                core_.status("encoding '" + editor_name_ + "' created");
            } else {
                core_.status("clone failed (exists or bad name)");
            }
        }
        editor_mode_ = false;
        return;
    }
    if (key == SDLK_BACKSPACE) {
        pop_utf8_char(editor_name_);
    }
}

void UiApp::on_editor_text(const char* text) {
    for (const char* p = text; *p != '\0'; ++p) {
        unsigned char c = static_cast<unsigned char>(*p);
        if (c > 0x20 && c < 0x7F) editor_name_.push_back(*p);
    }
}

void UiApp::on_keydown(const SDL_KeyboardEvent& ev) {
    if (editor_mode_) {
        on_editor_key(ev);
        return;
    }
    SDL_Keycode key = ev.keysym.sym;
    if (key == SDLK_ESCAPE) {
        if (editing_) {
            cancel_dial_edit();
            core_.status("edit cancelled");
            return;
        }
        SDL_Event q;
        q.type = SDL_QUIT;
        SDL_PushEvent(&q);
        return;
    }
    if (key == SDLK_F2) {
        if (f_mode_ == "spectrogram") {
            core_.status("encoding editor is available in pixel mode");
            return;
        }
        if (editing_) cancel_dial_edit();
        editor_mode_ = true;
        editor_name_.clear();
        core_.status("editor: type new encoding name, Enter to clone default, Esc back");
        return;
    }
    if (key == SDLK_TAB && !editing_) {
        int dir = (ev.keysym.mod & KMOD_SHIFT) ? -1 : 1;
        focus_ = (focus_ + dir + 7) % 7;
        return;
    }
    if (key == SDLK_SPACE && (focus_ == 4 || focus_ == 6) && !editing_ && compose_.empty()) {
        toggle_dial(focus_);
        return;
    }
    if (key == SDLK_RETURN || key == SDLK_KP_ENTER) {
        if (editing_) {
            apply_focus_field();
            editing_ = false;
            edit_snapshot_.clear();
            return;
        }
        if (!compose_.empty()) {
            std::string err;
            if (!core_.send_chat(compose_, err)) {
                core_.status(err);
                return;
            }
            compose_.clear();
            core_.status("sent | peers " + std::to_string(core_.peer_count()));
        }
        return;
    }
    if (key == SDLK_BACKSPACE) {
        if (editing_) {
            pop_utf8_char(editable_field_ref(focus_));
        } else {
            pop_utf8_char(compose_);
        }
    }
}

void UiApp::on_text_input(const char* text) {
    if (!text || text[0] == '\0') return;
    if (editor_mode_) {
        on_editor_text(text);
        return;
    }
    if (editing_) {
        if (focus_ == 3) {
            for (const char* p = text; *p != '\0'; ++p) {
                if (std::isdigit(static_cast<unsigned char>(*p))) f_port_.push_back(*p);
            }
        } else {
            std::string& field = editable_field_ref(focus_);
            field += text;
            if (focus_ == 2) field = truncate_utf8_chars(field, 16);
        }
        return;
    }
    // Avoid adding a space that already triggered a DISC/MODE toggle on empty compose.
    if (std::strcmp(text, " ") == 0 && (focus_ == 4 || focus_ == 6) && compose_.empty()) {
        return;
    }
    compose_ += text;
}

std::string UiApp::compose_prompt() const {
    if (editor_mode_) return "New encoding name: " + editor_name_ + "_";
    if (editing_) {
        return std::string("[") + kFieldLabels[focus_] + "] " +
               const_cast<UiApp*>(this)->editable_field_ref(focus_) + "_";
    }
    return "> " + compose_ + "_";
}

void UiApp::draw(SDL_Renderer* ren, int w, int h) {
    set_color(ren, kBgOuter);
    SDL_RenderClear(ren);

    // 1. Transceiver header + dial tiles.
    int dial_h = dial_height_for_width(w);
    SDL_Rect hdr_rect = {0, 0, w, dial_h};
    set_color(ren, kBgHeader);
    SDL_RenderFillRect(ren, &hdr_rect);
    set_color(ren, kBorderDim);
    SDL_RenderDrawLine(ren, 0, dial_h - 1, w, dial_h - 1);

    std::string values[7] = {
        f_freq_,
        f_chan_,
        f_call_,
        f_port_,
        to_upper(f_disc_),
        f_enc_,
        (f_mode_ == "spectrogram") ? "SPEC" : "PIXEL",
    };

    int cols = (w < 860) ? 4 : 7;
    int pad = 6;
    int tile_w = std::max(40, (w - pad * (cols + 1)) / cols);
    int tile_h = 30;
    for (int i = 0; i < 7; ++i) {
        int col_i = i % cols;
        int row_i = i / cols;
        SDL_Rect r = {pad + col_i * (tile_w + pad), 6 + row_i * (tile_h + 6), tile_w, tile_h};
        field_rects_[static_cast<size_t>(i)] = r;

        bool is_edit = editing_ && (i == focus_);
        bool is_focus = (i == focus_);
        set_color(ren, is_edit ? kBgTileEdit : (is_focus ? kBgTileFocus : kBgTile));
        SDL_RenderFillRect(ren, &r);
        set_color(ren, (is_edit || is_focus) ? kBorderFocus : kBorderDim);
        SDL_RenderDrawRect(ren, &r);

        SDL_Rect clip = {r.x + 4, r.y + 2, std::max(1, r.w - 8), r.h - 4};
        std::string lbl = std::string(kFieldLabels[i]) + " ";
        int lw = measure_text(font_small_, lbl);
        draw_text(ren, font_small_, lbl, r.x + 6, r.y + 7, kTextLabel, &clip);

        SDL_Color vcol = kTextMain;
        if (is_edit) {
            vcol = kTextEdit;
        } else if (i == 6) {
            vcol = (f_mode_ == "spectrogram") ? kAccentSpec : kAccentPixel;
        } else if (i == 4) {
            vcol = (f_disc_ == "lan") ? kBorderFocus : kAccentSpec;
        }
        std::string shown = values[i] + (is_edit ? "_" : "");
        draw_text(ren, font_small_, shown, r.x + 6 + lw, r.y + 7, vcol, &clip);
    }

    // Status telemetry bar along bottom of header.
    int status_y = dial_h - 23;
    size_t peers = core_.peer_count();
    SDL_Rect dot = {10, status_y + 5, 7, 7};
    set_color(ren, peers > 0 ? kAccentPixel : kBorderFocus);
    SDL_RenderFillRect(ren, &dot);
    std::string st = core_.current_status();
    if (st.size() > 80) st.resize(80);
    draw_text(ren, font_small_, st, 24, status_y, kTextMuted);
    std::string peer_badge = "PEERS " + std::to_string(peers);
    int pb_w = measure_text(font_small_, peer_badge);
    draw_text(ren, font_small_, peer_badge, w - pb_w - 12, status_y,
              peers > 0 ? kAccentPixel : kTextMuted);

    // 2. Compose deck geometry.
    int text_w = std::max(40, w - 20);
    int line_h = font_main_ ? std::max(TTF_FontHeight(font_main_), 18) : 18;
    std::string prompt = compose_prompt();
    std::vector<std::string> prompt_lines = wrap_text(
        prompt, text_w, [this](const std::string& s) { return measure_text(font_main_, s); });
    int help_h = 20;
    int max_compose = std::max(46, static_cast<int>(h * 0.40));
    int need_h = 12 + static_cast<int>(prompt_lines.size()) * line_h + help_h;
    int compose_h = std::min(std::max(46, need_h), max_compose);
    int max_lines = std::max(1, (compose_h - 12 - help_h) / line_h);
    if (static_cast<int>(prompt_lines.size()) > max_lines) {
        prompt_lines.erase(prompt_lines.begin(),
                           prompt_lines.begin() + static_cast<ptrdiff_t>(prompt_lines.size()) - max_lines);
    }

    // 3. Message viewport with cached textures.
    int log_h = std::max(1, h - dial_h - compose_h);
    SDL_Rect log_rect = {0, dial_h, w, log_h};
    set_color(ren, kBgLog);
    SDL_RenderFillRect(ren, &log_rect);

    int max_row_w = std::max(1, w - 22);
    uint64_t lver = core_.log_version();
    if (lver != cached_log_version_ || max_row_w != cached_max_w_) {
        rebuild_row_cache(ren, core_.log_entries(), max_row_w);
        cached_log_version_ = lver;
        cached_max_w_ = max_row_w;
    }

    std::vector<size_t> visible;
    int used_h = 0;
    for (int i = static_cast<int>(cached_rows_.size()) - 1; i >= 0; --i) {
        int rh = cached_rows_[static_cast<size_t>(i)].row_h;
        if (used_h + rh > log_h - 8) break;
        visible.push_back(static_cast<size_t>(i));
        used_h += rh;
    }
    SDL_RenderSetClipRect(ren, &log_rect);
    int cy = dial_h + log_h - 4 - used_h;
    for (int vi = static_cast<int>(visible.size()) - 1; vi >= 0; --vi) {
        const CachedRow& cr = cached_rows_[visible[static_cast<size_t>(vi)]];
        int top_gap = (cr.row_h - cr.h - kLineGap);
        int draw_y = cy + top_gap;
        SDL_Rect rail = {6, draw_y, 3, cr.h};
        set_color(ren, cr.local ? kRailTx : kRailRx);
        SDL_RenderFillRect(ren, &rail);
        if (cr.tex) {
            SDL_Rect dst = {14, draw_y, cr.w, cr.h};
            SDL_RenderCopy(ren, cr.tex, nullptr, &dst);
        }
        cy += cr.row_h;
    }
    SDL_RenderSetClipRect(ren, nullptr);

    // 4. Bottom compose deck.
    int comp_y = h - compose_h;
    SDL_Rect comp_rect = {0, comp_y, w, compose_h};
    set_color(ren, kBgCompose);
    SDL_RenderFillRect(ren, &comp_rect);
    set_color(ren, kBorderDim);
    SDL_RenderDrawLine(ren, 0, comp_y, w, comp_y);

    int ty = comp_y + 6;
    for (size_t i = 0; i < prompt_lines.size(); ++i) {
        draw_text(ren, font_main_, prompt_lines[i], 10, ty,
                  editing_ ? kTextEdit : kTextMain);
        ty += line_h;
    }
    draw_text(ren, font_small_,
              "Double-click dial to edit | Click DISC/MODE | Enter send/apply | F2 clone encoding | Esc quit",
              10, h - help_h + 2, kTextMuted);
}

int UiApp::run() {
    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        std::cerr << "SDL_Init failed: " << SDL_GetError() << "\n";
        return 1;
    }
    if (TTF_Init() != 0) {
        std::cerr << "TTF_Init failed: " << TTF_GetError() << "\n";
        SDL_Quit();
        return 1;
    }
    std::string mono_path = find_system_font(true);
    if (mono_path.empty()) {
        std::cerr << "No system monospace TTF font found.\n";
        TTF_Quit();
        SDL_Quit();
        return 1;
    }
    font_main_ = TTF_OpenFont(mono_path.c_str(), 15);
    font_small_ = TTF_OpenFont(mono_path.c_str(), 13);
    if (!font_main_ || !font_small_) {
        std::cerr << "TTF_OpenFont failed: " << TTF_GetError() << "\n";
        TTF_Quit();
        SDL_Quit();
        return 1;
    }

    SDL_Window* win = SDL_CreateWindow("R2P",
                                       SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                                       960, 540,
                                       SDL_WINDOW_RESIZABLE | SDL_WINDOW_SHOWN);
    if (!win) {
        std::cerr << "SDL_CreateWindow failed: " << SDL_GetError() << "\n";
        TTF_Quit();
        SDL_Quit();
        return 1;
    }
    SDL_Renderer* ren = SDL_CreateRenderer(win, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!ren) {
        ren = SDL_CreateRenderer(win, -1, SDL_RENDERER_SOFTWARE);
    }
    if (!ren) {
        std::cerr << "SDL_CreateRenderer failed: " << SDL_GetError() << "\n";
        SDL_DestroyWindow(win);
        TTF_Quit();
        SDL_Quit();
        return 1;
    }

    SDL_StartTextInput();
    core_.start();
    f_port_ = std::to_string(core_.listen_port());

    bool running = true;
    uint64_t last_ui = 0;
    uint64_t last_log = 0xFFFFFFFFFFFFFFFFULL;
    std::string last_status;
    size_t last_peers = 0xFFFFFFFFULL;
    int last_w = 0, last_h = 0;

    while (running) {
        SDL_Event ev;
        if (SDL_WaitEventTimeout(&ev, 33)) {
            do {
                if (ev.type == SDL_QUIT) {
                    running = false;
                } else if (ev.type == SDL_WINDOWEVENT) {
                    uint8_t we = ev.window.event;
                    if (we == SDL_WINDOWEVENT_EXPOSED ||
                        we == SDL_WINDOWEVENT_RESIZED ||
                        we == SDL_WINDOWEVENT_SIZE_CHANGED ||
                        we == SDL_WINDOWEVENT_RESTORED ||
                        we == SDL_WINDOWEVENT_SHOWN) {
                        ++ui_version_;
                    }
                } else if (ev.type == SDL_MOUSEBUTTONDOWN) {
                    on_mouse(ev.button);
                    ++ui_version_;
                } else if (ev.type == SDL_KEYDOWN) {
                    on_keydown(ev.key);
                    ++ui_version_;
                } else if (ev.type == SDL_TEXTINPUT) {
                    on_text_input(ev.text.text);
                    ++ui_version_;
                }
            } while (running && SDL_PollEvent(&ev));
        }

        int w = 0, h = 0;
        SDL_GetWindowSize(win, &w, &h);
        uint64_t lver = core_.log_version();
        std::string st = core_.current_status();
        size_t pc = core_.peer_count();
        if (ui_version_ != last_ui || lver != last_log || st != last_status ||
            pc != last_peers || w != last_w || h != last_h) {
            draw(ren, w, h);
            SDL_RenderPresent(ren);
            last_ui = ui_version_;
            last_log = lver;
            last_status = st;
            last_peers = pc;
            last_w = w;
            last_h = h;
        }
    }

    SDL_StopTextInput();
    clear_row_cache();
    core_.stop();
    cfg_ = core_.config_snapshot();
    save_config(cfg_);

    SDL_DestroyRenderer(ren);
    SDL_DestroyWindow(win);
    if (font_main_) { TTF_CloseFont(font_main_); font_main_ = nullptr; }
    if (font_small_) { TTF_CloseFont(font_small_); font_small_ = nullptr; }
    shutdown_send_font();
    TTF_Quit();
    SDL_Quit();
    return 0;
}

}  // namespace r2p
