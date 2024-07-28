find_package(PkgConfig REQUIRED)

# debug options
# set(CMAKE_VERBOSE_MAKEFILE ON)
# add_compile_options(-H)
# file(GLOB_RECURSE SOURCES "../include/ws_client/*.cpp")

# --------------------------------------
find_package(OpenSSL REQUIRED)
find_package(simdutf CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
pkg_check_modules(ZLIBNG REQUIRED IMPORTED_TARGET zlib-ng)

# --------------------------------------
add_executable(ex_hello_ws ex_hello_ws.cpp)
target_link_libraries(ex_hello_ws PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::ZLIBNG
    simdutf::simdutf
    websocketclient)
target_compile_definitions(ex_hello_ws PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=1 # Use simdutf for utf-8 validation
    WS_CLIENT_LOG_HANDSHAKE=1
    WS_CLIENT_LOG_MSG_PAYLOADS=1
    WS_CLIENT_LOG_MSG_SIZES=1
    WS_CLIENT_LOG_FRAMES=1
    WS_CLIENT_LOG_COMPRESSION=0)

# --------------------------------------
add_executable(ex_hello_wss ex_hello_wss.cpp)
target_link_libraries(ex_hello_wss PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::ZLIBNG
    simdutf::simdutf
    websocketclient)
target_compile_definitions(ex_hello_wss PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=1 # Use simdutf for utf-8 validation
    WS_CLIENT_LOG_HANDSHAKE=1
    WS_CLIENT_LOG_MSG_PAYLOADS=1
    WS_CLIENT_LOG_MSG_SIZES=1
    WS_CLIENT_LOG_FRAMES=1
    WS_CLIENT_LOG_COMPRESSION=0)

# --------------------------------------
add_executable(ex_echo_sync ex_echo_sync.cpp)
target_link_libraries(ex_echo_sync PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    simdutf::simdutf
    PkgConfig::ZLIBNG
    websocketclient)
target_compile_definitions(ex_echo_sync PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=1 # Use simdutf for utf-8 validation
    WS_CLIENT_LOG_HANDSHAKE=1
    WS_CLIENT_LOG_MSG_PAYLOADS=1
    WS_CLIENT_LOG_MSG_SIZES=1
    WS_CLIENT_LOG_FRAMES=1
    WS_CLIENT_LOG_COMPRESSION=0)

# --------------------------------------
add_executable(ex_echo_custom_logger ex_echo_custom_logger.cpp)
target_link_libraries(ex_echo_custom_logger PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    simdutf::simdutf
    PkgConfig::ZLIBNG
    websocketclient)
target_compile_definitions(ex_echo_custom_logger PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=1 # Use simdutf for utf-8 validation
    WS_CLIENT_LOG_HANDSHAKE=1
    WS_CLIENT_LOG_MSG_PAYLOADS=1
    WS_CLIENT_LOG_MSG_SIZES=1
    WS_CLIENT_LOG_FRAMES=1
    WS_CLIENT_LOG_COMPRESSION=0)

# --------------------------------------
add_executable(ex_binance_sync ex_binance_sync.cpp)
target_link_libraries(ex_binance_sync PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::ZLIBNG
    websocketclient)
target_compile_definitions(ex_binance_sync PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=0 # Use simdutf for utf-8 validation
    WS_CLIENT_VALIDATE_UTF8=0 # Disable utf-8 validation
    WS_CLIENT_LOG_HANDSHAKE=1
    WS_CLIENT_LOG_MSG_PAYLOADS=0
    WS_CLIENT_LOG_MSG_SIZES=0
    WS_CLIENT_LOG_FRAMES=0
    WS_CLIENT_LOG_COMPRESSION=0)
