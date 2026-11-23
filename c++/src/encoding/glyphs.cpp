#include "encoding/glyphs.hpp"

namespace r2p {

bool is_blank_glyph(const Glyph& g) {
    for (size_t i = 0; i < g.rows.size(); ++i) {
        if (g.rows[i] != 0) return false;
    }
    return true;
}

std::vector<std::vector<Glyph> > wrap_glyphs(const std::vector<Glyph>& glyphs,
                                             int max_width,
                                             int scale) {
    std::vector<std::vector<Glyph> > lines;
    if (glyphs.empty()) return lines;
    if (max_width <= 0) {
        lines.push_back(glyphs);
        return lines;
    }

    std::vector<Glyph> line;
    int line_w = 0;
    std::vector<Glyph> word;
    int word_w = 0;

    auto flush_word = [&]() {
        if (word.empty()) return;
        if (!line.empty() && line_w + word_w > max_width) {
            lines.push_back(line);
            line.clear();
            line_w = 0;
        }
        if (line.empty() && word_w > max_width) {
            for (size_t i = 0; i < word.size(); ++i) {
                int a = glyph_advance(word[i], scale);
                if (!line.empty() && line_w + a > max_width) {
                    lines.push_back(line);
                    line.clear();
                    line_w = 0;
                }
                line.push_back(word[i]);
                line_w += a;
            }
            word.clear();
            word_w = 0;
            return;
        }
        line.insert(line.end(), word.begin(), word.end());
        line_w += word_w;
        word.clear();
        word_w = 0;
    };

    for (size_t i = 0; i < glyphs.size(); ++i) {
        int a = glyph_advance(glyphs[i], scale);
        if (is_blank_glyph(glyphs[i])) {
            flush_word();
            if (!line.empty() && line_w + a > max_width) {
                lines.push_back(line);
                line.clear();
                line_w = 0;
            }
            if (!line.empty()) {
                line.push_back(glyphs[i]);
                line_w += a;
            }
        } else {
            word.push_back(glyphs[i]);
            word_w += a;
        }
    }
    flush_word();
    if (!line.empty()) lines.push_back(line);
    return lines;
}

}  // namespace r2p
