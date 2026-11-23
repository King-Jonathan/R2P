#include "ui/text_wrap.hpp"

namespace r2p {

void pop_utf8_char(std::string& s) {
    if (s.empty()) return;
    size_t i = s.size() - 1;
    while (i > 0 && (static_cast<unsigned char>(s[i]) & 0xC0) == 0x80) {
        --i;
    }
    s.resize(i);
}

std::vector<std::string> wrap_text(const std::string& text,
                                   int max_width,
                                   const std::function<int(const std::string&)>& measure) {
    std::vector<std::string> lines;
    if (text.empty()) {
        lines.push_back("");
        return lines;
    }
    if (max_width <= 0) {
        lines.push_back(text);
        return lines;
    }

    std::string cur;
    auto hard_append = [&](const std::string& token) {
        size_t i = 0;
        while (i < token.size()) {
            unsigned char c = static_cast<unsigned char>(token[i]);
            size_t step = 1;
            if ((c & 0xE0) == 0xC0) step = 2;
            else if ((c & 0xF0) == 0xE0) step = 3;
            else if ((c & 0xF8) == 0xF0) step = 4;
            if (i + step > token.size()) step = token.size() - i;
            std::string ch = token.substr(i, step);
            i += step;
            if (measure(cur + ch) <= max_width) {
                cur += ch;
            } else {
                if (!cur.empty()) lines.push_back(cur);
                cur = ch;
            }
        }
    };

    auto place_word = [&](const std::string& word) {
        if (word.empty()) return;
        if (cur.empty()) {
            if (measure(word) <= max_width) cur = word;
            else hard_append(word);
            return;
        }
        std::string trial = cur + " " + word;
        if (measure(trial) <= max_width) {
            cur = trial;
            return;
        }
        lines.push_back(cur);
        cur.clear();
        if (measure(word) <= max_width) cur = word;
        else hard_append(word);
    };

    size_t pos = 0;
    while (pos <= text.size()) {
        size_t sp = text.find(' ', pos);
        std::string word = (sp == std::string::npos) ? text.substr(pos) : text.substr(pos, sp - pos);
        if (word.empty()) {
            if (cur.empty()) {
                if (lines.empty() && measure(" ") <= max_width) cur = " ";
            } else if (measure(cur + " ") <= max_width) {
                cur += " ";
            } else {
                lines.push_back(cur);
                cur.clear();
            }
        } else {
            place_word(word);
        }
        if (sp == std::string::npos) break;
        pos = sp + 1;
    }

    if (!cur.empty() || lines.empty()) lines.push_back(cur);
    return lines;
}

}  // namespace r2p
