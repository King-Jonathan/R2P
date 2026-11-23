#ifndef R2P_ENCODING_GLYPHS_HPP
#define R2P_ENCODING_GLYPHS_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

namespace r2p {

struct Glyph {
    int w;
    int h;
    std::vector<uint32_t> rows;

    Glyph() : w(5), h(7), rows(7, 0) {}

    bool operator==(const Glyph& o) const {
        return w == o.w && h == o.h && rows == o.rows;
    }
};

inline int glyph_advance(const Glyph& g, int scale = 2) {
    return g.w * scale + scale;
}

bool is_blank_glyph(const Glyph& g);

std::vector<std::vector<Glyph> > wrap_glyphs(const std::vector<Glyph>& glyphs,
                                             int max_width,
                                             int scale = 2);

}  // namespace r2p

#endif
