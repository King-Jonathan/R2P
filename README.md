# R2P

R2P is a lightweight, peer-to-peer desktop chat app inspired by HAM shortwave radio. Pick the same virtual frequency, channel key, and message mode as someone else and you are in the same room—no accounts, no central chat server, and nothing saved to disk.

What makes R2P unusual is that the receiving app never turns a received message back into a text string - this serves as a proof of concept that the last layer of decryption can be done by the eyes/brain in some cases:

- **Pixel mode (`PIXEL`)**: Your text is converted into numeric codes (`0..255`) using `encodings.json`, and the receiver draws `5x7` pixel glyphs straight from those codes.
- **Spectrogram mode (`SPEC`)**: Your message is turned into audio whose frequencies trace out the shapes of the letters. The receiver computes a spectrogram of that audio so you read the message directly from the image.

Every chat and discovery packet is encrypted and authenticated with ChaCha20-Poly1305 using keys that rotate every five minutes. Peers find each other over Nostr relays, local LAN broadcasts, or both. Note that the client does not obfuscate your IP address, so use of a VPN is recommended for IP privacy.

## Getting Started

R2P comes with two interoperable implementations: **Python** in `python/` and **C++11** in `c++/`. Both speak the exact same wire protocol and can chat with each other directly.

### C++11 (Linux / WSL 2)

Requires a C++11 compiler, CMake, OpenSSL (`libssl-dev`), zlib (`zlib1g-dev`), SDL2 (`libsdl2-dev`), and SDL2_ttf (`libsdl2-ttf-dev`). On Ubuntu or Debian:

```bash
sudo apt update
sudo apt install g++ cmake pkg-config libssl-dev zlib1g-dev libsdl2-dev libsdl2-ttf-dev
```

Build and run from the `c++/` folder:

```bash
cd c++
cmake -B build
cmake --build build -j
./build/r2p
```

Pass a second config file (`./build/r2p second.json`) when running multiple local clients.

### Python — Windows (PowerShell)

You will need Python 3.10+ on a graphical desktop. Run the commands below from `python/` (where `requirements.txt` lives).

```powershell
cd python
py -3 -m venv .venv-win
.\.venv-win\Scripts\python.exe -m pip install --upgrade pip
.\.venv-win\Scripts\python.exe -m pip install -r requirements.txt
.\.venv-win\Scripts\python.exe -m r2p
```

### Python — Linux

On Ubuntu or Debian, make sure Python and `venv` are installed:

```bash
sudo apt update
sudo apt install python3 python3-venv
```

Then set up a virtual environment inside `python/` and launch the app:

```bash
cd python
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m r2p
```

### Python — Windows with WSL 2

Follow the Linux setup inside Ubuntu on WSL 2 (with WSLg enabled), and keep `.venv` separate from `.venv-win`. Once installed, you can launch it straight from PowerShell:

```powershell
wsl -d Ubuntu --cd '/mnt/c/path/to/R2P/python' -- .venv/bin/python -m r2p
```

If you want to run two clients on the same machine, pass a separate config file to the second one:

```bash
.venv/bin/python -m r2p second.json
```

## Controls

- **Dial bar**: Double-click `FREQ`, `CHAN`, `CALL`, `PORT`, or `ENC` to edit. Press `Enter` to apply or `Esc` to cancel.
- **Discovery & mode**: Click `DISC` to cycle `NOSTR`, `BOTH`, and `LAN`. Click `MODE` to switch between `PIXEL` and `SPEC`. When the compose bar is empty, `Tab` moves dial focus and `Space` switches `DISC` or `MODE`.
- **Chat**: Type in the bottom bar and press `Enter` to send. Your messages appear in blue; peer messages appear in green.
- **Custom pixel tables**: In `PIXEL` mode, press `F2`, type a name, and press `Enter` to clone the `default` table in `encodings.json`.
- **Quit**: Press `Esc` outside of an edit, or close the window.

## Running Tests

C++ tests (from `c++/`):

```bash
./build/r2p_tests
```

Python tests (from `python/`):

```bash
.venv/bin/python scripts/run_tests.py
```

## Further Reading

- [SPEC.md](SPEC.md) — Behavior, discovery rules, message modes, and security model.
- [DESIGN.md](DESIGN.md) — Wire formats, cryptography, threading, and module layout.
