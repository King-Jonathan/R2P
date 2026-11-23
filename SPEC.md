# R2P Product Specification

R2P is a peer-to-peer desktop chat program modeled on HAM shortwave radio. Users choose a virtual frequency, a channel key, and a message mode to join a room. Chat traffic travels directly between peers over IPv4 UDP.

## Peer Discovery

R2P supports three discovery settings controlled by `discovery_backend`: `nostr`, `both`, and `lan`.

- **Nostr (`KIND 20001`)**: Clients connect to configured WebSocket relays using a fresh ephemeral secp256k1 keypair per launch. Relays carry encrypted binary presence payloads, never chat messages.
- **Filter tags**: Each slot tag is `HMAC-SHA256(key=vibe_key, msg=b"r2p-nostr-tag-v2:" + protocol_byte)` encoded as 64 lowercase hex characters. Clients subscribe to and publish tags for the previous, current, and next 5-minute time slots. Non-matching events are dropped before signature verification and presence decryption.
- **Subscription and publish timing**: Clients publish immediately on relay connect, on every frequency, channel, or message-mode change, and at every 5-minute clock boundary (`:00`, `:05`, ..., `:55`). A newer setting change stays pending if it occurs during an awaited publish.
- **Direct UDP gossip**: When Nostr presence adds a new peer address, the client sends its own encrypted UDP discovery packet directly to that peer. Known peers are refreshed without another discovery packet.
- **LAN broadcast**: When `lan` or `both` is active, clients periodically broadcast encrypted UDP discovery packets on `255.255.255.255` across the bound port and the preferred port plus up to 3 offsets. Chat packets are sent only to known peers.
- **Presence and routing**: Binary presence holds an 8-byte per-process instance ID and up to 8 IPv4:port endpoints (default-route IP first). When Nostr is active, STUN Binding Requests run on the chat listen socket to discover the public mapped IPv4:port; in `lan`-only mode, STUN does not run. Clients pick a same-host loopback, same-`/24` LAN, same-NAT, or public IPv4 route. Received UDP discovery packets validate the encrypted presence body, ignore self packets, and add the UDP return address (falling back to the presence payload when received through a WSL2 NAT relay in the Python client).

## Message Modes

The `MODE` dial selects one active chat protocol: `PIXEL` (`0`) or `SPEC` (`2`). Chat packets for the inactive mode are dropped before decryption. Discovery (`1`) stays active in both modes.

- **Pixel mode**: The sender encodes `<callsign[:16]> ¦ <message>` to byte codes (`0..255`) using the active table in `encodings.json`, skipping characters absent from the table. The receiver maps code bytes directly to `5x7` bitmask glyphs and draws them.
- **Spectrogram mode**: The sender renders `<callsign[:16]> ¦ <message>` with a standard sans-serif font (raster height 24, max width 8192 columns), converts each column to a 48-sample signed 16-bit little-endian PCM frame via float32 inverse DFT/FFT, and compresses the PCM stream with raw DEFLATE (`wbits=-15`, level 6). The receiver decompresses the bounded stream (at most 786432 PCM bytes, divisible by 96, no trailing data), infers the column count from its length, runs a rectangular-window float32 STFT (48-sample windows, hop 48), and displays the grayscale spectrum tinted by TX/RX color.

Neither receive path builds a text string of chat content. The in-memory message log stores only glyph lists or grayscale spectrogram bitmaps and keeps at most `visible_lines` entries.

## Cryptography and Packets

- **Vibe key**: Derived every 5 minutes via `HKDF-SHA256(ikm=normalize_16(channel_key), salt=slot_u64_be, info=b"r2p-vibe-v2" || normalize_16(frequency), length=16)`. Clients keep previous, current, and next slot keys to tolerate clock skew.
- **Authenticated encryption**: Chat and discovery packet bodies use RFC 8439 ChaCha20-Poly1305 with a 32-byte HKDF body key, a 12-byte deterministic chunk nonce binding `(message_id, chunk_id, protocol)`, and the 26-byte packet header as associated data. Nostr presence payloads use ChaCha20-Poly1305 with a separate 32-byte HKDF presence key, a random 12-byte nonce, and fixed associated data `b"r2p-presence-v2"`.
- **Packet layout**: Every UDP datagram has a 26-byte header (`protocol`, 16-byte `room_id`, 6-byte `message_id`, 2-byte `chunk_id`, 1-byte `body_length`), followed by ciphertext + 16-byte tag, followed by random padding to a total length in `[200, 300]` bytes.
- **Chunking, pacing, and deduplication**: Payloads split into chunks up to 200 plaintext bytes (216 bytes with tag), with an empty final chunk when length is an exact multiple of 200. Complete messages are bounded to 2 MiB (`chunk_id <= 10485`). Each packet is sent twice with fresh padding and a random 5–20 ms delay; successive chat chunks are queued 2 ms apart. Deduplication tracks `(message_id, chunk_id)` for 10 minutes after AEAD verification (up to 4096 message IDs). Out-of-order reassembly holds up to 16 pending messages with a 60-second TTL. Delivery is best-effort UDP.

## User Controls

- The dial controls `FREQ`, `CHAN`, `CALL` (max 16 characters; applies to future sends), `PORT`, `DISC` (`NOSTR` / `BOTH` / `LAN`), `ENC`, and `MODE` (`PIXEL` / `SPEC`).
- Changing `FREQ`, `CHAN`, or `MODE` increments the room epoch, discards queued sends for the old mode, clears the log, pending reassemblies, and peers, updates discovery subscriptions, and publishes presence.
- Dial changes and exit save settings to the active config file, preserving the preferred UDP port even if the client had to bind a higher port.
- In `PIXEL` mode, `F2` opens a prompt to clone the `default` table in `encodings.json` under a new name and switch to it.

## Security and Operational Model

- Rooms use a shared secret: anyone holding the frequency and channel key can read and send messages and advertise peers.
- ChaCha20-Poly1305 authenticates every UDP header and body against modification by parties without the room key.
- `room_id` is a SHA-256 truncation of the normalized frequency, so low-entropy dial strings can be guessed offline; the channel key is never placed on the wire.
- `config.json` stores the channel key in clear text.
- Nostr relays and STUN servers can observe IP and timing metadata when Nostr discovery is enabled.
- Strict NATs or host firewalls may drop inbound UDP even after peer discovery succeeds.
