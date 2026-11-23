#ifndef R2P_ENCODING_SPECTROGRAM_TX_HPP
#define R2P_ENCODING_SPECTROGRAM_TX_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace r2p {

// Send path ONLY: renders standard-font text to 48-sample PCM and raw-DEFLATE compresses it.
// Never linked or invoked on the receive path.
bool text_to_audio(const std::string& text, std::vector<uint8_t>& out, std::string& error_out);

// Locate a standard sans font for spectrogram TX or mono font for UI.
std::string find_system_font(bool monospace);

// Close the cached send-path font handle (call before TTF_Quit).
void shutdown_send_font();

}  // namespace r2p

#endif
