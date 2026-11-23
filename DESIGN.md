# R2P — Design Reference

This document specifies the current architecture, wire formats, cryptography, concurrency model, and module layout of R2P. Product behavior is summarized in `SPEC.md`; installation and controls are in `README.md`.

---

## 1. Overview and Stack

R2P is a modular peer-to-peer UDP chat application built around five layers: `crypto`, `protocol`, `transport`, `discovery`, and `encoding`/`ui`, wired together by `AppCore`. Two wire-compatible implementations live side by side:

- **Python (`python/`)**: Python 3.10+, `pygame-ce>=2.5.0`, `cryptography>=42.0.0`, `websockets>=13.0`, `numpy>=2.0.0`, pure-Python BIP-340 Schnorr.
- **C++11 (`c++/`)**: C++11 (`-std=c++11`), CMake, OpenSSL (`SSL`/`Crypto` for TLS 1.2/1.3, ChaCha20-Poly1305, HKDF/HMAC-SHA256, CSPRNG, and constant-time secp256k1 BIP-340), `zlib`, `SDL2`, and `SDL2_ttf`. No third-party JSON, WebSocket, or FFT dependencies.

---

## 2. Repository Map

```text
R2P/
  README.md                    # overview, install, and controls
  SPEC.md                      # product specification
  DESIGN.md                    # architecture and wire reference
  LICENSE                      # MIT license
  c++/
    CMakeLists.txt             # builds r2p_core, r2p GUI binary, and r2p_tests
    config.json                # saved runtime configuration
    encodings.json             # named pixel encoding tables and 5x7 glyphs
    src/
      main.cpp                 # entry point: ./build/r2p [config.json]
      config.{hpp,cpp}         # Config load/save
      app_core.{hpp,cpp}       # wires crypto, protocol, transport, discovery, log
      util/
        base64.{hpp,cpp}       # hex and base64 codecs
        json.{hpp,cpp}         # strict RFC 8259 JSON parser/serializer
      crypto/
        vibe.{hpp,cpp}         # normalize_16, room_id_16, 5-min VibeKeys cache
        cipher.{hpp,cpp}       # RFC 8439 ChaCha20-Poly1305 AEAD, HKDF/HMAC-SHA256
        bip340.{hpp,cpp}       # constant-time BIP-340 Schnorr over OpenSSL secp256k1
      protocol/
        packet.{hpp,cpp}       # 26-byte header, AAD helper, random pad [200, 300]
        chunking.{hpp,cpp}     # callsign prepend, chunk split, MessageAssembler
        dedup.{hpp,cpp}        # bounded bitset DedupCache (10-min TTL)
      transport/
        udp_socket.{hpp,cpp}   # UDP bind/rebind with rollback, cond-timed send thread, STUN
      discovery/
        presence.{hpp,cpp}     # binary presence codec, getifaddrs local IPs, route pick
        peer_list.{hpp,cpp}    # bounded PeerList (max 64) with self-endpoint filter
        stun_client.{hpp,cpp}  # STUN Binding Request / XOR-MAPPED parser
        lan_backend.hpp        # periodic LAN UDP broadcast discovery
        ws_client.{hpp,cpp}    # minimal RFC 6455 WebSocket client over TCP + OpenSSL TLS
        nostr_backend.{hpp,cpp}# NIP-01 KIND 20001 ephemeral presence client
      encoding/
        glyphs.{hpp,cpp}       # 5x7 bitmask glyph layout and word wrap
        tables.{hpp,cpp}       # encodings.json loader, code-to-glyphs, clone_encoding
        spectrogram.{hpp,cpp}  # receive-only raw DEFLATE + 48-pt float32 STFT (no font deps)
        spectrogram_tx.{hpp,cpp}# send-only SDL2_ttf text render + 48-pt float32 IFFT
      ui/
        text_wrap.{hpp,cpp}    # UTF-8-aware compose/prompt word wrap
        app.{hpp,cpp}          # SDL2 + SDL2_ttf transceiver UI with cached row textures
    tests/
      test_main.cpp            # unit + loopback UDP tests including frozen Python v2 vectors
  python/
    config.json                # saved runtime configuration
    encodings.json             # named pixel encoding tables and 5x7 glyphs
    requirements.txt           # Python dependencies
    scripts/
      run_tests.py             # runs all unit tests without pytest
      probe_nostr.py           # sends a KIND 20001 test event to default relays
    r2p/
      __main__.py              # entry point: python -m r2p [config.json]
      config.py                # Config dataclass, load_config, save_config
      app_core.py              # wires crypto, protocol, transport, discovery, log
      crypto/
        vibe.py                # normalize_16, room_id_16, 5-min VibeKeys cache
        cipher.py              # RFC 8439 ChaCha20-Poly1305 AEAD, HMAC-SHA256 tags
        bip340.py              # pure-Python BIP-340 Schnorr for Nostr events
      protocol/
        packet.py              # 26-byte header, AAD helper, pad to [200, 300]
        chunking.py            # callsign prepend, chunk split, MessageAssembler
        dedup.py               # bounded bytearray-bitset DedupCache (10-min TTL)
      transport/
        udp_socket.py          # UDP bind/rebind, recv loop, condition-timed send thread, STUN
      platform/
        wsl_nat.py             # WSL2 NAT host LAN discovery and PowerShell UDP relay
      discovery/
        nostr_backend.py       # thin NIP-01 WebSocket client for KIND 20001 presence
        lan_backend.py         # periodic LAN UDP broadcast discovery
        stun_client.py         # minimal STUN Binding Request / XOR-MAPPED parser
        peer_list.py           # bounded PeerList (max 64) with self-endpoint filtering
        presence.py            # binary presence codec and IPv4 route selection
      encoding/
        tables.py              # encodings.json loader and code-to-glyph mapper
        glyphs.py              # 5x7 bitmask glyph renderer and word wrapper
        spectrogram.py         # FreeSans -> float32 IFFT -> raw DEFLATE -> float32 STFT
      ui/
        app.py                 # pygame main loop with expose-aware dirty-flag redraw
        dial_view.py           # responsive 1-row/2-row dial strip
        chat_view.py           # cached glyph and spectrogram surface log
        text_wrap.py           # compose/prompt word wrapper
        encoding_editor.py     # clones default table in encodings.json under a new name
    tests/                     # 15 test modules (91 unit tests)
```

---

## 3. Wire Protocol and Cryptography

Reference test vectors for all cryptographic primitives live in `python/tests/test_cipher.py`, `python/tests/test_packet.py`, `python/tests/test_bip340.py`, and `c++/tests/test_main.cpp`.

### 3.1 Input Normalization and `room_id`

```text
normalize_16(s):
  raw = utf8(s)
  if len(raw) == 16: return raw
  if len(raw) <  16: return raw || (0x00 * (16 - len(raw)))
  if len(raw) >  16: return SHA-256(raw)[:16]

room_id = SHA-256(normalize_16(frequency))[:16]
```

`VibeKeys` caches `room_id` on initialization and credential changes.

### 3.2 Vibe Key Rotation (5-Minute Slots)

```text
slot     = floor(unix_time / 300) * 300
salt     = slot as 8-byte big-endian uint64
ck       = normalize_16(channel_key)
freq     = normalize_16(frequency)
vibe_key = HKDF-SHA256(ikm=ck, salt=salt, info=b"r2p-vibe-v2" || freq, length=16)
```

`VibeKeys` builds a `VibeSnapshot` on each 5-minute slot boundary containing `last` (`slot - 300`), `current` (`slot`), and `next` (`slot + 300`), plus precomputed derived body keys, presence keys, and Nostr filter tags. Decryption tries `current` → `last` → `next`.

### 3.3 Authenticated Encryption (RFC 8439 ChaCha20-Poly1305)

HKDF `salt=None` uses the RFC 5869 32-byte zero salt.

- **Body key (32 bytes)**: `HKDF-SHA256(ikm=vibe_key, salt=None, info=b"r2p-body-v2", length=32)`
- **Presence key (32 bytes)**: `HKDF-SHA256(ikm=vibe_key, salt=None, info=b"r2p-presence-v2", length=32)`
- **UDP body AEAD**:
  - `nonce = SHA-256(message_id || chunk_id_u16_be || protocol_u8 || b"r2p-body-v2")[:12]`
  - `aad = packed 26-byte UDP header`
  - `body = ChaCha20Poly1305(body_key).encrypt(nonce, plaintext, aad)` (`len(plaintext) + 16` bytes)
- **Nostr presence AEAD**:
  - `nonce = random 12 bytes`
  - `aad = b"r2p-presence-v2"`
  - `cipher = nonce || ChaCha20Poly1305(presence_key).encrypt(nonce, binary_presence, aad)`
  - Transmitted in Nostr event `content` as standard ASCII base64.

### 3.4 Nostr Filter Tags (HMAC-SHA256)

For each slot (`last`, `current`, `next`) and active chat protocol (`0` or `2`):

```text
tag = HMAC-SHA256(key=vibe_key, msg=b"r2p-nostr-tag-v2:" || bytes([protocol])).hexdigest()
```

Each tag is 64 lowercase hex characters and is cached on `VibeSnapshot`.

### 3.5 UDP Packet Layout

Header is 26 bytes, big-endian, byte-aligned (`struct.Struct("!B16s6sHB")`):

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | `protocol`: `0` = pixel chat, `1` = discovery, `2` = spectrogram chat |
| 1 | 16 | `room_id`: `SHA-256(normalize_16(frequency))[:16]` |
| 17 | 6 | `message_id`: 6 random bytes |
| 23 | 2 | `chunk_id`: big-endian `uint16` (`0..10485`) |
| 25 | 1 | `body_length`: `0..255` (`MAX_BODY = 255`) |
| 26 | `body_length` | ChaCha20-Poly1305 ciphertext + 16-byte tag |
| `26 + body_length` | pad | random bytes so total datagram length is in `[200, 300]` |

Every outgoing packet is sent twice with fresh random padding; the second copy is scheduled with uniform jitter in `5..20 ms`.

### 3.6 Chunking, Reassembly, and Deduplication

- Chat text before encoding: `f"{callsign[:16]} ¦ {message}"` (`U+00A6` broken bar).
- Maximum chunk plaintext: `200` bytes (`216` bytes after 16-byte AEAD tag).
- If payload length is an exact multiple of `200`, an empty final chunk (`0` bytes plaintext, `16` bytes tag) is appended so the final chunk always satisfies `len(plaintext) < 200`.
- Complete message bound: `MAX_MESSAGE_BYTES = 2 MiB` (`MAX_VALID_CHUNK_ID = 10485`). Packets with `chunk_id > 10485` are dropped before decryption.
- `MessageAssembler`: up to `16` concurrent incomplete messages, `60 s` TTL, out-of-order completion without rescanning all chunks.
- `DedupCache`: tracks `(message_id, chunk_id)` after AEAD verification for `600 s`, max `4096` message IDs, using a bounded `bytearray` bitset per message (max `1311` bytes).

### 3.7 Binary Presence Format

```text
binary_presence = instance_id(8) || count(1) || count * (ipv4(4) || port_u16_be(2))
```

- `instance_id`: 8 random bytes per process launch.
- `count`: `1..8` (`MAX_PRESENCE_ENDPOINTS = 8`), max payload size `57` bytes.
- Loopback (`127.0.0.0/8`), `0.0.0.0`, port `0`, duplicates, and trailing bytes are rejected.

---

## 4. Discovery and Transport

### 4.1 Nostr (`python/r2p/discovery/nostr_backend.py`, `c++/src/discovery/nostr_backend.cpp`)

- Generates a fresh secp256k1 keypair on every launch (never written to disk).
- Publishes and subscribes to ephemeral `KIND 20001` events with `["t", tag]` for the previous, current, and next slots.
- Serializes `CLOSE` → `REQ` → `EVENT` (on an `asyncio` loop in Python, and a dedicated publisher thread + per-relay TLS WebSocket reader threads in C++), waking on settings changes, relay connects, and periodic ticks (quiet when offline). A revision counter keeps newer changes pending if triggered during an in-flight publish.
- Inbound events must match a cached `#t` tag before NIP-01 ID and BIP-340 signature verification and AEAD decryption.
- Default relays: `wss://relay.damus.io`, `wss://nos.lol`, `wss://relay.nostr.band`.

### 4.2 LAN, STUN, and Route Selection

- **LAN (`lan_backend.py` / `lan_backend.hpp`)**: Broadcasts encrypted `protocol=1` discovery packets every `30 s` (and immediately on startup or retune) to `255.255.255.255` on `{bound_port} ∪ {preferred_port + 0..3}`.
- **STUN (`stun_client.*`, `udp_socket.*`)**: Sends a STUN Binding Request on the chat listen socket off the UI thread when Nostr discovery is enabled (`nostr` or `both`). In `lan`-only mode, STUN does not run and no public IP is queried.
- **Route selection (`presence.*` `pick_send_addr`)**:
  1. Same-host local IP with a different port → `127.0.0.1:port`
  2. Private RFC1918 IPv4 on the same `/24` as a local IP
  3. Same-NAT peer (advertising our `public_ip`): another IPv4 advertised alongside it, or `127.0.0.1:port` if only `public_ip` on a different port
  4. Non-private IPv4 that is not our `public_ip`
  5. First remaining IPv4 candidate
- **Inbound UDP discovery**: Validates the encrypted binary presence body, ignores own `instance_id`, and adds the UDP source address (rewriting same-host local IPs with a different port to `127.0.0.1`). When received through the Python WSL2 NAT relay, falls back to `ingest_presence`. No reply packet is sent.

### 4.3 UDP Socket and WSL2 NAT Relay

- **Bind and rebind (`udp_socket.*`)**: Binds the preferred port without `SO_REUSEADDR`; if busy, scans up to 64 higher ports. Failed rebinds keep the previous port active.
- **Paced sender thread**: A dedicated sender thread waits on a condition variable using monotonic deadlines, preserving 2 ms chunk pacing and 5–20 ms copy jitter with zero idle polling.
- **WSL2 NAT (`python/r2p/platform/wsl_nat.py`, Python only)**: Active only on WSL2 NAT guests lacking a non-Hyper-V LAN IPv4. Starts a Windows PowerShell UDP relay forwarding inbound packets to the guest IPv4 and advertises the Windows host LAN IPv4. Stopped by `atexit`, main-thread `SIGTERM`/`SIGINT` hooks (which delegate to prior handlers), and a 5-second heartbeat timeout.

---

## 5. Encoding and Display

### 5.1 Pixel Mode (`tables.*`, `glyphs.*`)

`encodings.json` maps named sets to `encoding` (`char -> 0..255`) and `decoding` (`code -> list of {w, h, rows}` 5×7 bitmasks, MSB = leftmost pixel). Both UIs render wrapped glyph rows into cached surfaces/textures (`pygame.Surface` in Python, `SDL_Texture` in C++) and blit them on draw.

### 5.2 Spectrogram Mode (`spectrogram.*`, `spectrogram_tx.*`)

- **Send**: Renders text with a standard sans-serif font (`pygame` bundled `FreeSans` 16pt in Python; `SDL2_ttf` system sans 15pt in C++) into a `24 × (width + 4)` uint8 bitmap (`width + 4 <= 8192`), maps rows to frequency bins `1..24` (high frequency at top) of a 48-sample `float32` real inverse DFT/FFT (normalized by `/48`) with gain `28000`, rounds to signed 16-bit little-endian PCM, and compresses with raw DEFLATE (`wbits=-15`, level 6).
- **Receive**: Decompresses raw DEFLATE with output cap `8192 * 96 + 1` bytes, requires nonzero length divisible by `96`, `width <= 8192`, `eof`, and no trailing data, runs a 48-sample `float32` real forward DFT/FFT (`hop = 48`), maps bin `1..24` magnitudes back to `0..255` grayscale bytes, wraps on blank column gaps (`>= 3` columns), and caches tinted rows. In C++, the receive path (`spectrogram.cpp`) has zero font or `SDL2_ttf` dependencies.
- **Local TX echo**: Runs `audio_to_spectrogram` on the compressed PCM so the sender sees the same spectrum the receiver computes.

---

## 6. Concurrency and UI

- **Room epoch (`room_epoch`)**: Incremented on every frequency, channel, or mode change. Send and receive paths run heavy encoding, FFT, DEFLATE, and AEAD outside the core lock, then verify `room_epoch` under lock before committing logs, enqueuing sends, or learning peers.
- **Atomic backend swap**: `set_discovery_backend` detaches active backends before stopping them and clears cached public STUN state when leaving Nostr.
- **Cached local IPs**: `local_ipv4_addresses()` places the default-route IP first and is cached on startup, UDP rebind, and 5-minute slot boundaries.
- **UI redraw (`python/r2p/ui/app.py`, `c++/src/ui/app.cpp`)**: Tracks UI/log version, status text, peer count, and window size, redrawing only on state changes or window expose/restore/show events. Narrow windows wrap the dial bar into two rows.

---

## 7. Key Data Flows

### Send Chat

```text
UI compose
  → snapshot (epoch, callsign, protocol, tables, room_id, body_key) under lock
  → build_message_body(callsign, text)
  → pixel: encode_text → codes_to_glyphs
  → spectrogram: render_text → float32 irfft → raw DEFLATE → audio_to_spectrogram
  → chunk_body (max 200, empty final if exact multiple)
  → per chunk: pack_header (AAD) → ChaCha20-Poly1305 body_encrypt
  → lock & verify epoch → append local LogEntry, record message_id, enqueue 2 copies/peer (2 ms chunk pace, 5–20 ms jitter)
```

### Receive UDP

```text
UDP datagram
  → STUN Binding Success? parse XOR-MAPPED addr; done
  → unpack_packet (len in [200, 300], 26-byte header) & chunk_id <= 10485
  → lock: check room_id & active protocol (or discovery), snapshot epoch
  → ChaCha20-Poly1305 body_decrypt (AAD = header) trying current/last/next
  → lock & verify epoch → dedup (message_id, chunk_id)
  → protocol 1: decode binary presence (skip self) → add return addr (or ingest_presence via WSL relay)
  → protocol 0 or 2: skip recent TX → assembler.feed
  → unlocked: codes_to_glyphs or audio_to_spectrogram
  → lock & verify epoch → append remote LogEntry + learn peer addr (if not relay/self)
```

### Nostr Discovery

```text
STUN on listen socket (when Nostr active) → XOR-MAPPED ip:port
  → binary presence = instance_id(8) || count(1) || count * (ipv4(4) || port_u16_be(2))
  → endpoint_encrypt: random 12-byte nonce || ChaCha20-Poly1305(presence_key, b"r2p-presence-v2") → base64
  → filter tag = HMAC-SHA256(vibe_key, b"r2p-nostr-tag-v2:" + bytes([protocol])).hexdigest()
  → EVENT kind 20001 with previous/current/next #t tags
  → inbound EVENT: skip own pubkey → match cached #t tag → verify NIP-01 id & BIP-340 sig → AEAD decrypt → decode binary presence
  → new peer address: send direct encrypted UDP discovery packet (no reply on receipt)
```

---

## 8. Configuration Reference (`config.json`)

Code defaults live in `python/r2p/config.py` and `c++/src/config.hpp`. Dial edits and clean exit save these fields to the active config file (`encodings_path` is accepted on load with default `encodings.json`).

| Key | Description | Default |
|-----|-------------|---------|
| `default_callsign` | Callsign (max 16 chars) | `Booperator` |
| `frequency` | Virtual frequency string | `7.074` |
| `channel_key` | Channel secret string | `liberty` |
| `udp_port` | Preferred UDP listen port (`1..65535`) | `19302` |
| `visible_lines` | Max in-memory log entries | `20` |
| `encoding` | Table name in `encodings.json` | `default` |
| `message_mode` | `pixel` or `spectrogram` | `pixel` |
| `nostr_relays` | List of `wss://` relay URLs | damus.io, nos.lol, relay.nostr.band |
| `stun_server` | STUN `host:port` | `stun.l.google.com:19302` |
| `discovery_backend` | `nostr`, `lan`, or `both` | `nostr` |

---

## 9. Security and Interoperability Notes

- **AEAD & key domains**: Every UDP header and body is authenticated by ChaCha20-Poly1305 (`r2p-body-v2`), Nostr presence uses a separate key and AAD (`r2p-presence-v2`), and Nostr filter tags use `HMAC-SHA256` directly over `vibe_key` (`r2p-nostr-tag-v2:`).
- **Cross-implementation wire parity**: Both implementations share exact `HKDF-SHA256`, `HMAC-SHA256`, `ChaCha20-Poly1305`, `BIP-340`, raw DEFLATE (`wbits = -15`), and `/48`-normalized 48-sample `float32` real DFT/IDFT audio framing.
- **Operational limits**: Shared-secret room model (no per-user authentication), best-effort UDP without retransmissions beyond dual-send, and NAT/firewall traversal depends on peer network configuration.

---

## 10. Test Suites

- **C++11 (`c++/`)**: `cmake -B build && cmake --build build -j && ./build/r2p_tests` — covers frozen Python v2 HKDF/AEAD/HMAC vectors, official BIP-340 vectors, packet/chunking/dedup, binary presence/STUN/Nostr filtering, pixel + raw-DEFLATE float32 spectrogram, two-`AppCore` loopback UDP chat in both modes, mode isolation, room epoch, 3-way `DISC` cycling, and UTF-8 text wrapping.
- **Python (`python/`)**: `.venv/bin/python scripts/run_tests.py` — 91 unit tests across `python/tests/` covering crypto vectors, BIP-340, packet bounds, out-of-order chunk reassembly, bounded dedup/assembler/peer caches, presence routing, STUN, Nostr discovery, LAN/3-way `DISC` toggling, WSL2 NAT relay, spectrogram receive-side isolation, and UI text/glyph wrapping.
