#include "encoding/tables.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>

#include "util/json.hpp"

namespace r2p {

namespace {

bool read_file_text(const std::string& path, std::string& out) {
    std::ifstream fh(path.c_str(), std::ios::binary);
    if (!fh) return false;
    std::ostringstream ss;
    ss << fh.rdbuf();
    out = ss.str();
    return true;
}

bool write_file_text(const std::string& path, const std::string& text) {
    std::ofstream fh(path.c_str(), std::ios::binary | std::ios::trunc);
    if (!fh) return false;
    fh.write(text.data(), static_cast<std::streamsize>(text.size()));
    return fh.good();
}

Glyph parse_glyph(const Json& obj) {
    Glyph g;
    const Json* jw = obj.get("w");
    const Json* jh = obj.get("h");
    g.w = (jw && jw->is_int() && jw->as_int() > 0 && jw->as_int() <= 32)
              ? static_cast<int>(jw->as_int()) : 5;
    g.h = (jh && jh->is_int() && jh->as_int() > 0 && jh->as_int() <= 32)
              ? static_cast<int>(jh->as_int()) : 7;
    uint32_t mask = (g.w >= 32) ? 0xFFFFFFFFu : ((1u << g.w) - 1u);
    g.rows.assign(static_cast<size_t>(g.h), 0);
    const Json* jrows = obj.get("rows");
    if (jrows && jrows->is_array()) {
        const std::vector<Json>& arr = jrows->as_array();
        for (size_t i = 0; i < arr.size() && i < static_cast<size_t>(g.h); ++i) {
            if (arr[i].is_int()) {
                g.rows[i] = static_cast<uint32_t>(arr[i].as_int()) & mask;
            }
        }
    }
    return g;
}

std::vector<Glyph> parse_glyph_list(const Json& val) {
    std::vector<Glyph> out;
    if (val.is_object()) {
        out.push_back(parse_glyph(val));
    } else if (val.is_array()) {
        const std::vector<Json>& arr = val.as_array();
        for (size_t i = 0; i < arr.size(); ++i) {
            if (arr[i].is_object() && (arr[i].get("rows") || arr[i].get("w"))) {
                out.push_back(parse_glyph(arr[i]));
            }
        }
    }
    return out;
}

}  // namespace

bool load_encodings(const std::string& path, std::map<std::string, EncodingTables>& out) {
    std::string raw;
    if (!read_file_text(path, raw)) return false;
    Json root;
    if (!Json::parse(raw, root) || !root.is_object()) return false;

    out.clear();
    const std::map<std::string, Json>& top = root.as_object();
    for (std::map<std::string, Json>::const_iterator it = top.begin(); it != top.end(); ++it) {
        if (!it->second.is_object()) continue;
        EncodingTables t;
        t.name = it->first;
        const Json* enc = it->second.get("encoding");
        if (enc && enc->is_object()) {
            const std::map<std::string, Json>& em = enc->as_object();
            for (std::map<std::string, Json>::const_iterator e = em.begin(); e != em.end(); ++e) {
                if (e->second.is_int() && e->second.as_int() >= 0 && e->second.as_int() <= 255) {
                    t.char_to_code[e->first] = static_cast<uint8_t>(e->second.as_int());
                }
            }
        }
        const Json* dec = it->second.get("decoding");
        if (dec && dec->is_object()) {
            const std::map<std::string, Json>& dm = dec->as_object();
            for (std::map<std::string, Json>::const_iterator d = dm.begin(); d != dm.end(); ++d) {
                char* endp = nullptr;
                long code = std::strtol(d->first.c_str(), &endp, 10);
                uint8_t key = 0;
                if (endp != d->first.c_str() && *endp == '\0' && code >= 0 && code <= 255) {
                    key = static_cast<uint8_t>(code);
                } else if (d->first == "space" && t.char_to_code.count("space")) {
                    key = t.char_to_code["space"];
                } else {
                    continue;
                }
                std::vector<Glyph> gl = parse_glyph_list(d->second);
                if (!gl.empty()) t.code_to_glyphs[key] = gl;
            }
        }
        out[it->first] = t;
    }
    return !out.empty();
}

bool clone_encoding(const std::string& path, const std::string& source, const std::string& new_name) {
    if (new_name.empty()) return false;
    std::string raw;
    if (!read_file_text(path, raw)) return false;
    Json root;
    if (!Json::parse(raw, root) || !root.is_object()) return false;
    const Json* src = root.get(source);
    if (!src || root.get(new_name)) return false;
    root.set(new_name, *src);
    return write_file_text(path, root.dump_pretty() + "\n");
}

std::vector<uint8_t> encode_text(const EncodingTables& tables, const std::string& utf8_text) {
    std::vector<uint8_t> out;
    out.reserve(utf8_text.size());
    size_t i = 0;
    while (i < utf8_text.size()) {
        unsigned char c = static_cast<unsigned char>(utf8_text[i]);
        size_t step = 1;
        if ((c & 0xE0) == 0xC0) step = 2;
        else if ((c & 0xF0) == 0xE0) step = 3;
        else if ((c & 0xF8) == 0xF0) step = 4;
        if (i + step > utf8_text.size()) break;
        std::string ch = utf8_text.substr(i, step);
        i += step;

        std::map<std::string, uint8_t>::const_iterator it = tables.char_to_code.find(ch);
        if (it == tables.char_to_code.end() && ch == " ") {
            it = tables.char_to_code.find("space");
        }
        if (it != tables.char_to_code.end()) {
            out.push_back(it->second);
        }
    }
    return out;
}

std::vector<Glyph> codes_to_glyphs(const EncodingTables& tables, const std::vector<uint8_t>& codes) {
    std::vector<Glyph> out;
    out.reserve(codes.size());
    for (size_t i = 0; i < codes.size(); ++i) {
        std::map<uint8_t, std::vector<Glyph> >::const_iterator it =
            tables.code_to_glyphs.find(codes[i]);
        if (it != tables.code_to_glyphs.end()) {
            out.insert(out.end(), it->second.begin(), it->second.end());
        }
    }
    return out;
}

}  // namespace r2p
