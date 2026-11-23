#ifndef R2P_UI_TEXT_WRAP_HPP
#define R2P_UI_TEXT_WRAP_HPP

#include <functional>
#include <string>
#include <vector>

namespace r2p {

std::vector<std::string> wrap_text(const std::string& text,
                                   int max_width,
                                   const std::function<int(const std::string&)>& measure);

// Remove the last UTF-8 codepoint from a string.
void pop_utf8_char(std::string& s);

}  // namespace r2p

#endif
