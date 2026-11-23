cmake_minimum_required(VERSION 3.16)
project(r2p LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SDL2 REQUIRED sdl2)
pkg_check_modules(SDL2_TTF REQUIRED SDL2_ttf)

add_compile_options(-Wall -Wextra -Wpedantic)

set(R2P_CORE_SOURCES
    src/config.cpp
    src/app_core.cpp
    src/util/base64.cpp
    src/util/json.cpp
    src/crypto/cipher.cpp
    src/crypto/vibe.cpp
    src/crypto/bip340.cpp
    src/protocol/packet.cpp
    src/protocol/chunking.cpp
    src/protocol/dedup.cpp
    src/transport/udp_socket.cpp
    src/discovery/presence.cpp
    src/discovery/peer_list.cpp
    src/discovery/stun_client.cpp
    src/discovery/ws_client.cpp
    src/discovery/nostr_backend.cpp
    src/encoding/glyphs.cpp
    src/encoding/tables.cpp
    src/encoding/spectrogram.cpp
    src/encoding/spectrogram_tx.cpp
)

add_library(r2p_core STATIC ${R2P_CORE_SOURCES})
target_include_directories(r2p_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${SDL2_INCLUDE_DIRS}
    ${SDL2_TTF_INCLUDE_DIRS}
)
target_link_libraries(r2p_core PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    Threads::Threads
    ${SDL2_LIBRARIES}
    ${SDL2_TTF_LIBRARIES}
)

add_executable(r2p
    src/main.cpp
    src/ui/text_wrap.cpp
    src/ui/app.cpp
)
target_link_libraries(r2p PRIVATE r2p_core)

add_executable(r2p_tests
    tests/test_main.cpp
    src/ui/text_wrap.cpp
)
target_link_libraries(r2p_tests PRIVATE r2p_core)
