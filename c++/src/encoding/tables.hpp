#ifndef R2P_ENCODING_TABLES_HPP
#define R2P_ENCODING_TABLES_HPP

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "encoding/glyphs.hpp"

namespace r2p {

struct EncodingTables {
    std::string name;
    std::map<std::string, uint8_t> char_to_code;
    std::map<uint8_t, std::vector<Glyph> > code_to_glyphs;
};

bool load_encodings(const std::string& path, std::map<std::string, EncodingTables>& out);
bool clone_encoding(const std::string& path, const std::string& source, const std::string& new_name);

// Encode UTF-8 text into byte codes (skip unknown characters).
std::vector<uint8_t> encode_text(const EncodingTables& tables, const std::string& utf8_text);

// Map code bytes directly to glyphs without building a text string.
std::vector<Glyph> codes_to_glyphs(const EncodingTables& tables, const std::vector<uint8_t>& codes);

}  // namespace r2p

#endif
