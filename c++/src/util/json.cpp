#include "util/json.hpp"

#include <cstdio>
#include <cstdlib>

namespace r2p {

namespace {

static const int kMaxDepth = 32;

void append_utf8(uint32_t cp, std::string& out) {
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0x10FFFF) {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

void dump_string(const std::string& s, std::string& out) {
    out.push_back('"');
    for (size_t i = 0; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
}

class Parser {
public:
    explicit Parser(const std::string& s) : s_(s), pos_(0) {}

    bool parse_root(Json& out) {
        skip_ws();
        if (!parse_value(out, 0)) return false;
        skip_ws();
        return pos_ == s_.size();
    }

private:
    const std::string& s_;
    size_t pos_;

    void skip_ws() {
        while (pos_ < s_.size()) {
            char c = s_[pos_];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                ++pos_;
            } else {
                break;
            }
        }
    }

    bool parse_value(Json& out, int depth) {
        if (depth > kMaxDepth || pos_ >= s_.size()) return false;
        char c = s_[pos_];
        if (c == '"') {
            std::string str;
            if (!parse_string(str)) return false;
            out = Json::make_string(str);
            return true;
        }
        if (c == '{') return parse_object(out, depth + 1);
        if (c == '[') return parse_array(out, depth + 1);
        if (c == 't') return parse_literal("true", Json::make_bool(true), out);
        if (c == 'f') return parse_literal("false", Json::make_bool(false), out);
        if (c == 'n') return parse_literal("null", Json::make_null(), out);
        if (c == '-' || (c >= '0' && c <= '9')) return parse_number(out);
        return false;
    }

    bool parse_literal(const char* lit, const Json& val, Json& out) {
        size_t i = 0;
        while (lit[i] != '\0') {
            if (pos_ >= s_.size() || s_[pos_] != lit[i]) return false;
            ++pos_;
            ++i;
        }
        out = val;
        return true;
    }

    bool parse_hex4(uint32_t& out) {
        if (pos_ + 4 > s_.size()) return false;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            char c = s_[pos_++];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<uint32_t>(c - 'A' + 10);
            else return false;
        }
        out = v;
        return true;
    }

    bool parse_string(std::string& out) {
        if (pos_ >= s_.size() || s_[pos_] != '"') return false;
        ++pos_;
        out.clear();
        while (pos_ < s_.size()) {
            unsigned char c = static_cast<unsigned char>(s_[pos_++]);
            if (c == '"') return true;
            if (c < 0x20) return false;
            if (c != '\\') {
                out.push_back(static_cast<char>(c));
                continue;
            }
            if (pos_ >= s_.size()) return false;
            char esc = s_[pos_++];
            switch (esc) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    uint32_t cp = 0;
                    if (!parse_hex4(cp)) return false;
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        if (pos_ + 2 > s_.size() || s_[pos_] != '\\' || s_[pos_ + 1] != 'u') {
                            return false;
                        }
                        pos_ += 2;
                        uint32_t low = 0;
                        if (!parse_hex4(low) || low < 0xDC00 || low > 0xDFFF) return false;
                        cp = 0x10000 + (((cp - 0xD800) << 10) | (low - 0xDC00));
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        return false;
                    }
                    append_utf8(cp, out);
                    break;
                }
                default: return false;
            }
        }
        return false;
    }

    bool parse_number(Json& out) {
        size_t start = pos_;
        if (s_[pos_] == '-') ++pos_;
        if (pos_ >= s_.size()) return false;
        if (s_[pos_] == '0') {
            ++pos_;
        } else if (s_[pos_] >= '1' && s_[pos_] <= '9') {
            while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') ++pos_;
        } else {
            return false;
        }
        bool is_float = false;
        if (pos_ < s_.size() && s_[pos_] == '.') {
            is_float = true;
            ++pos_;
            if (pos_ >= s_.size() || s_[pos_] < '0' || s_[pos_] > '9') return false;
            while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') ++pos_;
        }
        if (pos_ < s_.size() && (s_[pos_] == 'e' || s_[pos_] == 'E')) {
            is_float = true;
            ++pos_;
            if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-')) ++pos_;
            if (pos_ >= s_.size() || s_[pos_] < '0' || s_[pos_] > '9') return false;
            while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') ++pos_;
        }
        std::string token = s_.substr(start, pos_ - start);
        if (is_float) {
            out = Json::make_int(static_cast<int64_t>(std::strtod(token.c_str(), nullptr)));
            return true;
        }
        char* endp = nullptr;
        long long v = std::strtoll(token.c_str(), &endp, 10);
        if (endp != token.c_str() + token.size()) return false;
        out = Json::make_int(static_cast<int64_t>(v));
        return true;
    }

    bool parse_array(Json& out, int depth) {
        ++pos_;  // '['
        out = Json::make_array();
        skip_ws();
        if (pos_ < s_.size() && s_[pos_] == ']') {
            ++pos_;
            return true;
        }
        while (pos_ < s_.size()) {
            skip_ws();
            Json elem;
            if (!parse_value(elem, depth)) return false;
            out.push(elem);
            skip_ws();
            if (pos_ >= s_.size()) return false;
            if (s_[pos_] == ']') {
                ++pos_;
                return true;
            }
            if (s_[pos_] != ',') return false;
            ++pos_;
        }
        return false;
    }

    bool parse_object(Json& out, int depth) {
        ++pos_;  // '{'
        out = Json::make_object();
        skip_ws();
        if (pos_ < s_.size() && s_[pos_] == '}') {
            ++pos_;
            return true;
        }
        while (pos_ < s_.size()) {
            skip_ws();
            std::string key;
            if (!parse_string(key)) return false;
            skip_ws();
            if (pos_ >= s_.size() || s_[pos_] != ':') return false;
            ++pos_;
            skip_ws();
            Json val;
            if (!parse_value(val, depth)) return false;
            out.set(key, val);
            skip_ws();
            if (pos_ >= s_.size()) return false;
            if (s_[pos_] == '}') {
                ++pos_;
                return true;
            }
            if (s_[pos_] != ',') return false;
            ++pos_;
        }
        return false;
    }
};

}  // namespace

std::string Json::dump_compact() const {
    std::string out;
    switch (type_) {
        case kNull: return "null";
        case kBool: return bool_val_ ? "true" : "false";
        case kInt: {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(int_val_));
            return std::string(buf);
        }
        case kString:
            dump_string(str_val_, out);
            return out;
        case kArray:
            out.push_back('[');
            for (size_t i = 0; i < arr_val_.size(); ++i) {
                if (i > 0) out.push_back(',');
                out += arr_val_[i].dump_compact();
            }
            out.push_back(']');
            return out;
        case kObject:
            out.push_back('{');
            bool first = true;
            for (std::map<std::string, Json>::const_iterator it = obj_val_.begin();
                 it != obj_val_.end(); ++it) {
                if (!first) out.push_back(',');
                first = false;
                dump_string(it->first, out);
                out.push_back(':');
                out += it->second.dump_compact();
            }
            out.push_back('}');
            return out;
    }
    return "null";
}

std::string Json::dump_pretty(int indent) const {
    if (type_ != kArray && type_ != kObject) return dump_compact();
    std::string pad(static_cast<size_t>(indent), ' ');
    std::string child(static_cast<size_t>(indent + 2), ' ');
    std::string out;
    if (type_ == kArray) {
        if (arr_val_.empty()) return "[]";
        out += "[\n";
        for (size_t i = 0; i < arr_val_.size(); ++i) {
            out += child + arr_val_[i].dump_pretty(indent + 2);
            if (i + 1 < arr_val_.size()) out.push_back(',');
            out.push_back('\n');
        }
        out += pad + "]";
        return out;
    }
    if (obj_val_.empty()) return "{}";
    out += "{\n";
    size_t count = 0;
    for (std::map<std::string, Json>::const_iterator it = obj_val_.begin();
         it != obj_val_.end(); ++it) {
        out += child;
        dump_string(it->first, out);
        out += ": ";
        out += it->second.dump_pretty(indent + 2);
        if (++count < obj_val_.size()) out.push_back(',');
        out.push_back('\n');
    }
    out += pad + "}";
    return out;
}

bool Json::parse(const std::string& text, Json& out) {
    Parser p(text);
    return p.parse_root(out);
}

}  // namespace r2p
