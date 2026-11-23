#ifndef R2P_UI_APP_HPP
#define R2P_UI_APP_HPP

#include <SDL.h>
#include <SDL_ttf.h>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "app_core.hpp"
#include "config.hpp"

namespace r2p {

class UiApp {
public:
    explicit UiApp(const Config& cfg);
    ~UiApp();

    UiApp(const UiApp&) = delete;
    UiApp& operator=(const UiApp&) = delete;

    int run();

private:
    struct CachedRow {
        SDL_Texture* tex;
        int w;
        int h;
        int row_h;
        bool local;
        bool is_first_of_msg;
    };

    void clear_row_cache();
    void rebuild_row_cache(SDL_Renderer* ren, const std::vector<LogEntry>& entries, int max_w);
    SDL_Texture* make_glyph_row_texture(SDL_Renderer* ren,
                                        const std::vector<Glyph>& row,
                                        SDL_Color color,
                                        int scale,
                                        int max_w,
                                        int& out_w,
                                        int& out_h);
    SDL_Texture* make_spectrogram_row_texture(SDL_Renderer* ren,
                                              const Spectrogram& row,
                                              SDL_Color color);

    void draw(SDL_Renderer* ren, int w, int h);
    int dial_height_for_width(int w) const { return (w < 860) ? 104 : 68; }
    int hit_test_dial(int px, int py) const;

    void on_mouse(const SDL_MouseButtonEvent& ev);
    void on_keydown(const SDL_KeyboardEvent& ev);
    void on_text_input(const char* text);
    void on_editor_key(const SDL_KeyboardEvent& ev);
    void on_editor_text(const char* text);

    void toggle_dial(int idx);
    void begin_dial_edit(int idx);
    void cancel_dial_edit();
    void apply_focus_field();
    std::string& editable_field_ref(int idx);
    std::string compose_prompt() const;
    int measure_text(TTF_Font* font, const std::string& text) const;
    void draw_text(SDL_Renderer* ren, TTF_Font* font, const std::string& text,
                   int x, int y, SDL_Color color, const SDL_Rect* clip = nullptr);

    Config cfg_;
    AppCore core_;

    // Dial state
    std::string f_freq_;
    std::string f_chan_;
    std::string f_call_;
    std::string f_port_;
    std::string f_disc_;
    std::string f_enc_;
    std::string f_mode_;
    int focus_;
    bool editing_;
    std::string edit_snapshot_;
    std::array<SDL_Rect, 7> field_rects_;

    // Compose / F2 editor state
    std::string compose_;
    bool editor_mode_;
    std::string editor_name_;
    uint64_t ui_version_;

    // Fonts & cached chat row textures
    TTF_Font* font_main_;
    TTF_Font* font_small_;
    uint64_t cached_log_version_;
    int cached_max_w_;
    std::vector<CachedRow> cached_rows_;
};

}  // namespace r2p

#endif
