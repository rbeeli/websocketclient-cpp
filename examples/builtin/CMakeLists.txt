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
add_executable(ex_hello_ws_builtin ex_hello_ws_builtin.cpp)
target_link_libraries(ex_hello_ws_builtin PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::ZLIBNG
    simdutf::simdutf
    websocketclient)
target_compile_definitions(ex_hello_ws_builtin PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=1 # Use simdutf for utf-8 validation
    WS_CLIENT_LOG_HANDSHAKE=1
    WS_CLIENT_LOG_MSG_PAYLOADS=1
    WS_CLIENT_LOG_MSG_SIZES=1
    WS_CLIENT_LOG_FRAMES=1
    WS_CLIENT_LOG_COMPRESSION=0)

# --------------------------------------
add_executable(ex_hello_wss_builtin ex_hello_wss_builtin.cpp)
target_link_libraries(ex_hello_wss_builtin PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::ZLIBNG
    simdutf::simdutf
    websocketclient)
target_compile_definitions(ex_hello_wss_builtin PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=1 # Use simdutf for utf-8 validation
    WS_CLIENT_LOG_HANDSHAKE=1
    WS_CLIENT_LOG_MSG_PAYLOADS=1
    WS_CLIENT_LOG_MSG_SIZES=1
    WS_CLIENT_LOG_FRAMES=1
    WS_CLIENT_LOG_COMPRESSION=0)

# --------------------------------------
add_executable(ex_echo_builtin ex_echo_builtin.cpp)
target_link_libraries(ex_echo_builtin PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    simdutf::simdutf
    PkgConfig::ZLIBNG
    websocketclient)
target_compile_definitions(ex_echo_builtin PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=1 # Use simdutf for utf-8 validation
    WS_CLIENT_LOG_HANDSHAKE=1
    WS_CLIENT_LOG_MSG_PAYLOADS=1
    WS_CLIENT_LOG_MSG_SIZES=1
    WS_CLIENT_LOG_FRAMES=1
    WS_CLIENT_LOG_COMPRESSION=0)

# --------------------------------------
add_executable(ex_custom_logger_builtin ex_custom_logger_builtin.cpp)
target_link_libraries(ex_custom_logger_builtin PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    simdutf::simdutf
    PkgConfig::ZLIBNG
    websocketclient)
target_compile_definitions(ex_custom_logger_builtin PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=1 # Use simdutf for utf-8 validation
    WS_CLIENT_LOG_HANDSHAKE=1
    WS_CLIENT_LOG_MSG_PAYLOADS=1
    WS_CLIENT_LOG_MSG_SIZES=1
    WS_CLIENT_LOG_FRAMES=1
    WS_CLIENT_LOG_COMPRESSION=0)

# --------------------------------------
add_executable(ex_binance_builtin ex_binance_builtin.cpp)
target_link_libraries(ex_binance_builtin PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::ZLIBNG
    websocketclient)
target_compile_definitions(ex_binance_builtin PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=0 # Use simdutf for utf-8 validation
    WS_CLIENT_VALIDATE_UTF8=0 # Disable utf-8 validation
    WS_CLIENT_LOG_HANDSHAKE=1
    WS_CLIENT_LOG_MSG_PAYLOADS=0
    WS_CLIENT_LOG_MSG_SIZES=0
    WS_CLIENT_LOG_FRAMES=0
    WS_CLIENT_LOG_COMPRESSION=0)

# --------------------------------------
add_executable(ex_reconnect_builtin ex_reconnect_builtin.cpp)
target_link_libraries(ex_reconnect_builtin PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::ZLIBNG
    websocketclient)
target_compile_definitions(ex_reconnect_builtin PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=0 # Use simdutf for utf-8 validation
    WS_CLIENT_VALIDATE_UTF8=0 # Disable utf-8 validation
    WS_CLIENT_LOG_HANDSHAKE=1
    WS_CLIENT_LOG_MSG_PAYLOADS=0
    WS_CLIENT_LOG_MSG_SIZES=0
    WS_CLIENT_LOG_FRAMES=0
    WS_CLIENT_LOG_COMPRESSION=0)

# --------------------------------------
add_executable(ex_wait_message_wss_builtin ex_wait_message_wss_builtin.cpp)
target_link_libraries(ex_wait_message_wss_builtin PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::ZLIBNG
    websocketclient)
target_compile_definitions(ex_wait_message_wss_builtin PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=0 # Use simdutf for utf-8 validation
    WS_CLIENT_VALIDATE_UTF8=0 # Disable utf-8 validation
    WS_CLIENT_LOG_HANDSHAKE=1
    WS_CLIENT_LOG_MSG_PAYLOADS=0
    WS_CLIENT_LOG_MSG_SIZES=0
    WS_CLIENT_LOG_FRAMES=0
    WS_CLIENT_LOG_COMPRESSION=0)
