#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "app_core.hpp"
#include "config.hpp"
#include "crypto/bip340.hpp"
#include "crypto/cipher.hpp"
#include "crypto/vibe.hpp"
#include "discovery/nostr_backend.hpp"
#include "discovery/peer_list.hpp"
#include "discovery/presence.hpp"
#include "discovery/stun_client.hpp"
#include "encoding/glyphs.hpp"
#include "encoding/spectrogram.hpp"
#include "encoding/spectrogram_tx.hpp"
#include "encoding/tables.hpp"
#include "protocol/chunking.hpp"
#include "protocol/dedup.hpp"
#include "protocol/packet.hpp"
#include "ui/text_wrap.hpp"
#include "util/base64.hpp"
#include "util/json.hpp"

using namespace r2p;

namespace {

template <size_t N>
std::array<uint8_t, N> from_hex_arr(const std::string& hex) {
    std::vector<uint8_t> v;
    bool ok = hex_decode(hex, v);
    assert(ok && v.size() == N);
    std::array<uint8_t, N> out;
    std::memcpy(out.data(), &v[0], N);
    return out;
}

void test_crypto_python_vectors() {
    // Exact frozen v2 vectors from python/tests/test_cipher.py (slot 1700000000).
    const std::string VIBE_HEX = "7bb4577b91389b34a6b9e48323c51c49";
    const std::string EKEY_HEX = "40d45e43ce1b6b85456a1bb3614c822cc4281bbc2a0b7d3bf082d4d2e0622ff0";
    const std::string PKEY_HEX = "97d67c671b09a22f8f5f44d30b4a0ddc3c48dcdebe68bc200ce7e1e47acdb901";
    const std::string BODY0_HEX = "9bc42afa91a4af4eb028ceccc3be34bd6cc620489b725459";
    const std::string BODY1_HEX = "47dbd42521ce67c0f332f510df2d8ed747d868625c8a5946";
    const std::string ENDPT_HEX = "000102030405060708090a0ba83e2091bfbfa4c9966001d2afbadaebd2b3669d5815d282166f8dd461a5b1d6e2";
    const std::string TAG0_HEX = "476d13db94e46e0e4156a0e60033888c57315b4978fd254b1ee4d2fcd0d0d0ac";
    const std::string TAG2_HEX = "1ea961dda1a618578e3d883fe9f9c2ce5781ecca80dd7435e19e9959ef8b0f11";

    std::array<uint8_t, 16> vibe = vibe_key_for_slot("liberty", "7.074", 1700000000);
    std::array<uint8_t, 32> ekey = expand_body_key(vibe);
    std::array<uint8_t, 32> pkey = expand_presence_key(vibe);
    assert(hex_encode(vibe.data(), 16) == VIBE_HEX);
    assert(hex_encode(ekey.data(), 32) == EKEY_HEX);
    assert(hex_encode(pkey.data(), 32) == PKEY_HEX);
    assert(nostr_filter_tag(vibe, kProtocolPixel) == TAG0_HEX);
    assert(nostr_filter_tag(vibe, kProtocolSpectrogram) == TAG2_HEX);
    assert(nostr_filter_tag(vibe, kProtocolDiscovery).empty());

    std::array<uint8_t, 6> mid = {{'m', 's', 'g', 'i', 'd', '!'}};
    std::array<uint8_t, 16> room;
    room.fill(0x11);
    const uint8_t plain[8] = {0x01, 0x02, 0x03, 'h', 'e', 'l', 'l', 'o'};
    std::array<uint8_t, kHeaderBytes> aad0, aad1;
    assert(pack_header(0, room, mid, 0, sizeof(plain) + kAeadTagBytes, aad0));
    assert(pack_header(1, room, mid, 0, sizeof(plain) + kAeadTagBytes, aad1));

    std::vector<uint8_t> c0, c1, dec;
    assert(body_encrypt(ekey, mid, 0, plain, sizeof(plain), 0, aad0.data(), aad0.size(), c0));
    assert(body_encrypt(ekey, mid, 0, plain, sizeof(plain), 1, aad1.data(), aad1.size(), c1));
    assert(hex_encode(c0) == BODY0_HEX);
    assert(hex_encode(c1) == BODY1_HEX);
    assert(body_decrypt(ekey, mid, 0, &c0[0], c0.size(), 0, aad0.data(), aad0.size(), dec));
    assert(dec.size() == sizeof(plain) && std::memcmp(&dec[0], plain, sizeof(plain)) == 0);
    c0[0] ^= 1;
    assert(!body_decrypt(ekey, mid, 0, &c0[0], c0.size(), 0, aad0.data(), aad0.size(), dec));
    assert(!body_decrypt(ekey, mid, 0, &c1[0], c1.size(), 1, aad0.data(), aad0.size(), dec));

    std::array<uint8_t, kNonceBytes> nonce;
    for (size_t i = 0; i < kNonceBytes; ++i) nonce[i] = static_cast<uint8_t>(i);
    const std::string ep_plain = "203.0.113.5:19302";
    std::vector<uint8_t> ep_ct, ep_dec;
    assert(endpoint_encrypt_with_nonce(
        pkey, nonce, reinterpret_cast<const uint8_t*>(ep_plain.data()), ep_plain.size(), ep_ct));
    assert(hex_encode(ep_ct) == ENDPT_HEX);
    assert(endpoint_decrypt(pkey, &ep_ct[0], ep_ct.size(), ep_dec));
    assert(std::string(ep_dec.begin(), ep_dec.end()) == ep_plain);
    assert(!endpoint_decrypt(ekey, &ep_ct[0], ep_ct.size(), ep_dec));
}

void test_bip340_vectors() {
    std::array<uint8_t, 32> pub0 = from_hex_arr<32>("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
    std::array<uint8_t, 32> msg0 = from_hex_arr<32>("0000000000000000000000000000000000000000000000000000000000000000");
    std::array<uint8_t, 64> sig0 = from_hex_arr<64>(
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");
    assert(bip340_verify(msg0, sig0, pub0));

    std::array<uint8_t, 32> pub1 = from_hex_arr<32>("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
    std::array<uint8_t, 32> msg1 = from_hex_arr<32>("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
    std::array<uint8_t, 64> sig1 = from_hex_arr<64>(
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
        "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A");
    assert(bip340_verify(msg1, sig1, pub1));

    sig0[0] ^= 1;
    assert(!bip340_verify(msg0, sig0, pub0));

    std::array<uint8_t, 32> priv, pub;
    assert(bip340_generate_keypair(priv, pub));
    std::array<uint8_t, 64> sig;
    assert(bip340_sign(msg1, priv, sig));
    assert(bip340_verify(msg1, sig, pub));
}

void test_packet_chunking_dedup_json() {
    Packet p;
    p.protocol = kProtocolSpectrogram;
    p.room_id = room_id_16("7.074");
    p.message_id = new_message_id();
    p.chunk_id = 300;
    p.body.assign(20, 0xAB);
    std::vector<uint8_t> raw1, raw2;
    assert(pack_packet(p, raw1) && pack_packet(p, raw2));
    assert(raw1.size() >= kPadMin && raw1.size() <= kPadMax);
    assert(raw1 != raw2);
    Packet u;
    assert(unpack_packet(raw1, u));
    assert(u.protocol == p.protocol && u.room_id == p.room_id &&
           u.message_id == p.message_id && u.chunk_id == 300 && u.body == p.body);

    std::vector<uint8_t> payload(400, 0x42);
    std::vector<std::vector<uint8_t> > chunks;
    assert(chunk_body(payload, chunks, 200));
    assert(chunks.size() == 3 && chunks[2].empty());
    MessageAssembler asm_(200);
    std::vector<uint8_t> complete;
    assert(!asm_.feed(p.message_id, 2, chunks[2], complete, 100.0));
    assert(!asm_.feed(p.message_id, 0, chunks[0], complete, 100.0));
    assert(asm_.feed(p.message_id, 1, chunks[1], complete, 100.0));
    assert(complete == payload);

    DedupCache dedup(600.0, 4);
    assert(!dedup.is_duplicate(p.message_id, 0, 10.0));
    assert(dedup.is_duplicate(p.message_id, 0, 10.0));
    assert(dedup.is_duplicate(p.message_id, 65535, 10.0));
    assert(!dedup.is_duplicate(p.message_id, 0, 610.0));

    std::vector<uint8_t> b64_in(17, 0x5A), b64_out;
    assert(base64_decode(base64_encode(b64_in), b64_out) && b64_out == b64_in);
    Json j;
    assert(Json::parse("{\"a\":1,\"b\":[\"hi\\u00a6\",true,null]}", j));
    assert(j.is_object() && j.get("a")->as_int() == 1);
}

void test_presence_stun_and_nostr() {
    std::array<uint8_t, kInstanceIdBytes> inst = from_hex_arr<8>("aabbccddeeff0011");
    std::vector<Endpoint> eps;
    eps.push_back(Endpoint("127.0.0.1", 19302));
    eps.push_back(Endpoint("203.0.113.1", 19302));
    eps.push_back(Endpoint("192.168.1.5", 19302));
    eps.push_back(Endpoint("192.168.1.5", 19302));
    std::vector<uint8_t> bin = encode_presence(inst, eps);
    assert(bin.size() == 9 + 6 * 2);

    std::array<uint8_t, kInstanceIdBytes> inst2;
    std::vector<Endpoint> eps2;
    assert(decode_presence(bin.data(), bin.size(), inst2, eps2));
    assert(inst2 == inst && eps2.size() == 2 && eps2[0] == Endpoint("203.0.113.1", 19302));

    // Trailing byte and loopback rejected.
    bin.push_back(0);
    assert(!decode_presence(bin.data(), bin.size(), inst2, eps2));

    // Same-host loopback rewrite & same-NAT LAN pick.
    Endpoint picked;
    std::set<std::string> locals;
    locals.insert("192.168.1.10");
    std::set<Endpoint> ours;
    ours.insert(Endpoint("203.0.113.9", 19302));
    ours.insert(Endpoint("192.168.1.10", 19302));
    ours.insert(Endpoint("127.0.0.1", 19302));
    std::vector<Endpoint> same_host = {Endpoint("203.0.113.9", 19303), Endpoint("192.168.1.10", 19303)};
    assert(pick_send_addr(same_host, "203.0.113.9", locals, 19302, ours, picked));
    assert(picked == Endpoint("127.0.0.1", 19303));
    std::vector<Endpoint> same_nat = {Endpoint("203.0.113.9", 19302), Endpoint("192.168.1.20", 19302)};
    assert(pick_send_addr(same_nat, "203.0.113.9", locals, 19302, ours, picked));
    assert(picked == Endpoint("192.168.1.20", 19302));

    // STUN XOR-MAPPED-ADDRESS parse (203.0.113.42:54321).
    std::array<uint8_t, 12> tx;
    tx.fill(0x33);
    std::vector<uint8_t> stun(32, 0);
    stun[0] = 0x01; stun[1] = 0x01;  // Binding Success
    stun[2] = 0x00; stun[3] = 0x0C;  // len 12
    stun[4] = 0x21; stun[5] = 0x12; stun[6] = 0xA4; stun[7] = 0x42;
    std::memcpy(&stun[8], tx.data(), 12);
    stun[20] = 0x00; stun[21] = 0x20;  // XOR-MAPPED-ADDRESS
    stun[22] = 0x00; stun[23] = 0x08;
    stun[25] = 0x01;  // IPv4
    uint16_t xport = static_cast<uint16_t>(54321 ^ (kStunMagic >> 16));
    stun[26] = static_cast<uint8_t>(xport >> 8);
    stun[27] = static_cast<uint8_t>(xport & 0xFF);
    uint32_t xip = ((203u << 24) | (0u << 16) | (113u << 8) | 42u) ^ kStunMagic;
    stun[28] = static_cast<uint8_t>((xip >> 24) & 0xFF);
    stun[29] = static_cast<uint8_t>((xip >> 16) & 0xFF);
    stun[30] = static_cast<uint8_t>((xip >> 8) & 0xFF);
    stun[31] = static_cast<uint8_t>(xip & 0xFF);
    Endpoint mapped;
    assert(parse_stun_mapped_address(stun.data(), stun.size(), &tx, mapped));
    assert(mapped == Endpoint("203.0.113.42", 54321));

    // Nostr event build, verify, filter tag isolation, and decrypt callback.
    VibeKeys vk("liberty", "7.074");
    std::vector<std::vector<uint8_t> > received;
    NostrDiscoveryBackend pub_b(std::vector<std::string>(), &vk, kProtocolPixel,
                                [&]() { return encode_presence(inst, eps); });
    NostrDiscoveryBackend sub_b(std::vector<std::string>(), &vk, kProtocolPixel,
                                []() { return std::vector<uint8_t>(); },
                                [&](const std::vector<uint8_t>& raw, uint8_t proto) {
                                    assert(proto == kProtocolPixel);
                                    received.push_back(raw);
                                });
    VibeSnapshot snap = vk.refresh();
    std::vector<uint8_t> pbytes = encode_presence(inst, eps);
    std::vector<uint8_t> p_ct;
    assert(endpoint_encrypt(snap.presence_current, pbytes.data(), pbytes.size(), p_ct));
    Json tags = Json::make_array();
    Json t0 = Json::make_array();
    t0.push(Json::make_string("t"));
    t0.push(Json::make_string(snap.nostr_tags(kProtocolPixel)[1]));
    tags.push(t0);
    Json ev = build_nostr_event(pub_b.privkey(), pub_b.pubkey_hex(),
                                kNostrKindEphemeral, tags, base64_encode(p_ct));
    assert(verify_nostr_event(ev));
    Json frame = Json::make_array();
    frame.push(Json::make_string("EVENT"));
    frame.push(Json::make_string("r2p"));
    frame.push(ev);
    sub_b.handle_message(frame.dump_compact());
    assert(received.size() == 1 && received[0] == pbytes);

    // Wrong mode must drop event before callback.
    NostrDiscoveryBackend spec_b(std::vector<std::string>(), &vk, kProtocolSpectrogram,
                                 []() { return std::vector<uint8_t>(); },
                                 [&](const std::vector<uint8_t>&, uint8_t) { assert(false); });
    spec_b.handle_message(frame.dump_compact());
}

void test_encoding_and_spectrogram() {
    std::map<std::string, EncodingTables> tables;
    assert(load_encodings("encodings.json", tables));
    assert(tables.count("default") == 1);
    std::vector<uint8_t> codes = encode_text(tables["default"], "Aa0 ¦ !");
    assert(codes.size() == 7);
    std::vector<Glyph> glyphs = codes_to_glyphs(tables["default"], codes);
    assert(glyphs.size() == 7);

    // Pure tone at bin 8 maps to row (HEIGHT - 8).
    std::vector<uint8_t> tone_pcm(kPcmBytesPerColumn);
    for (int n = 0; n < kFftSize; ++n) {
        double v = 10000.0 * std::cos(2.0 * 3.14159265358979323846 * 8.0 * n / kFftSize);
        int16_t s = static_cast<int16_t>(std::nearbyint(v));
        uint16_t u = static_cast<uint16_t>(s);
        tone_pcm[n * 2] = static_cast<uint8_t>(u & 0xFF);
        tone_pcm[n * 2 + 1] = static_cast<uint8_t>((u >> 8) & 0xFF);
    }
    std::vector<uint8_t> tone_deflated;
    assert(deflate_raw(tone_pcm.data(), tone_pcm.size(), tone_deflated));
    Spectrogram tone_spec;
    assert(audio_to_spectrogram(tone_deflated, tone_spec));
    assert(tone_spec.width == 1);
    int peak_row = 0;
    for (int r = 1; r < kSpectrogramHeight; ++r) {
        if (tone_spec.pixels[r] > tone_spec.pixels[peak_row]) peak_row = r;
    }
    assert(peak_row == kSpectrogramHeight - 8);

    // Full text -> audio -> spectrogram roundtrip & invalid rejection.
    std::vector<uint8_t> audio;
    std::string err;
    assert(text_to_audio("TestOp \xC2\xA6 Hello C++11!", audio, err));
    Spectrogram spec;
    assert(audio_to_spectrogram(audio, spec));
    assert(spec.width > 40 && spec.pixels.size() == static_cast<size_t>(kSpectrogramHeight * spec.width));
    std::vector<Spectrogram> wrapped = wrap_spectrogram(spec, 50);
    assert(wrapped.size() > 1);

    // Reject empty, corrupt, trailing, and oversized audio.
    Spectrogram bad;
    assert(!audio_to_spectrogram(std::vector<uint8_t>(), bad));
    std::vector<uint8_t> trailing = audio;
    trailing.push_back(0xAA);
    assert(!audio_to_spectrogram(trailing, bad));
    std::vector<uint8_t> oversized_pcm((kMaxColumns + 1) * kPcmBytesPerColumn, 0);
    std::vector<uint8_t> oversized_def;
    assert(deflate_raw(oversized_pcm.data(), oversized_pcm.size(), oversized_def));
    assert(!audio_to_spectrogram(oversized_def, bad));
}

void test_loopback_udp_chat_pixel_and_spectrogram() {
    Config ca, cb;
    ca.udp_port = 41510;
    cb.udp_port = 41511;
    ca.discovery_backend = "lan";
    cb.discovery_backend = "lan";
    ca.nostr_relays.clear();
    cb.nostr_relays.clear();
    ca.default_callsign = "Alpha";
    cb.default_callsign = "Bravo";
    ca.encodings_path = "encodings.json";
    cb.encodings_path = "encodings.json";

    AppCore a(ca);
    AppCore b(cb);
    assert(a.start() && b.start());
    a.add_peer(Endpoint("127.0.0.1", b.listen_port()));
    b.add_peer(Endpoint("127.0.0.1", a.listen_port()));

    // Pixel two-way transfer.
    std::string err;
    assert(a.send_chat("Hello from C++ pixel!", err));
    for (int i = 0; i < 100 && b.log_entries().empty(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    assert(b.log_entries().size() == 1 && !b.log_entries()[0].local);
    assert(b.log_entries()[0].glyphs == a.log_entries()[0].glyphs);

    // Mode isolation: switch A to spectrogram while B stays in pixel -> B drops silently.
    assert(a.set_message_mode("spectrogram"));
    a.add_peer(Endpoint("127.0.0.1", b.listen_port()));
    assert(a.send_chat("Only spectrogram peers should see this.", err));
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    assert(b.log_entries().size() == 1);  // unchanged

    // Switch B to spectrogram and do two-way audio spectrogram transfer over UDP.
    assert(b.set_message_mode("spectrogram"));
    a.add_peer(Endpoint("127.0.0.1", b.listen_port()));
    b.add_peer(Endpoint("127.0.0.1", a.listen_port()));
    assert(a.send_chat("Spectrogram over real UDP!", err));
    for (int i = 0; i < 200 && b.log_entries().empty(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    assert(b.log_entries().size() == 1 && b.log_entries()[0].is_spectrogram);
    assert(b.log_entries()[0].spectrogram == a.log_entries().back().spectrogram);

    // 3-way discovery backend cycle & epoch advance on channel change.
    uint64_t ep0 = a.room_epoch();
    a.set_channel_key("new-secret");
    assert(a.room_epoch() == ep0 + 1 && a.peer_count() == 0);
    assert(a.cycle_discovery_backend() == "nostr");
    assert(a.cycle_discovery_backend() == "both");
    assert(a.cycle_discovery_backend() == "lan");

    a.stop();
    b.stop();
}

void test_text_wrap() {
    auto measure = [](const std::string& s) { return static_cast<int>(s.size()); };
    std::vector<std::string> lines = wrap_text("hello world", 8, measure);
    assert(lines.size() == 2 && lines[0] == "hello" && lines[1] == "world");
    std::vector<std::string> hard = wrap_text("abcdefgh", 3, measure);
    assert(hard.size() == 3 && hard[0] == "abc" && hard[1] == "def" && hard[2] == "gh");
    std::string u = "a\xC2\xA6";
    pop_utf8_char(u);
    assert(u == "a");
}

}  // namespace

int main() {
    test_crypto_python_vectors();
    std::cout << "OK test_crypto_python_vectors\n";
    test_bip340_vectors();
    std::cout << "OK test_bip340_vectors\n";
    test_packet_chunking_dedup_json();
    std::cout << "OK test_packet_chunking_dedup_json\n";
    test_presence_stun_and_nostr();
    std::cout << "OK test_presence_stun_and_nostr\n";
    test_encoding_and_spectrogram();
    std::cout << "OK test_encoding_and_spectrogram\n";
    test_loopback_udp_chat_pixel_and_spectrogram();
    std::cout << "OK test_loopback_udp_chat_pixel_and_spectrogram\n";
    test_text_wrap();
    std::cout << "OK test_text_wrap\n";
    shutdown_send_font();
    std::cout << "All C++ tests passed\n";
    return 0;
}
