find_package(PkgConfig REQUIRED)

# debug options
# set(CMAKE_VERBOSE_MAKEFILE ON)
# add_compile_options(-H)
# file(GLOB_RECURSE SOURCES "../include/ws_client/*.cpp")


# copy cert.pem public key to build directory
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/certs/cert.pem
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

# --------------------------------------
find_package(asio CONFIG REQUIRED)

# find_package(wolfssl CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(simdutf CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
pkg_check_modules(ZLIBNG REQUIRED IMPORTED_TARGET zlib-ng)

# --------------------------------------
add_executable(ex_hello ex_hello.cpp)
target_link_libraries(ex_hello PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::ZLIBNG
    simdutf::simdutf
    websocketclient)
target_compile_definitions(ex_hello PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=1 # Use simdutf for utf-8 validation
)

# --------------------------------------
add_executable(ex_echo ex_echo.cpp)
target_link_libraries(ex_echo PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    simdutf::simdutf
    PkgConfig::ZLIBNG
    websocketclient
)
target_compile_definitions(ex_echo PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=1 # Use simdutf for utf-8 validation
)

# --------------------------------------
add_executable(ex_echo_custom_logger ex_echo_custom_logger.cpp)
target_link_libraries(ex_echo_custom_logger PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    simdutf::simdutf
    PkgConfig::ZLIBNG
    websocketclient
)
target_compile_definitions(ex_echo_custom_logger PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=1 # Use simdutf for utf-8 validation
)

# --------------------------------------
add_executable(ex_binance_sync ex_binance_sync.cpp)
target_link_libraries(ex_binance_sync PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::ZLIBNG
    websocketclient
)
target_compile_definitions(ex_binance_sync PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=0 # Use simdutf for utf-8 validation
    WS_CLIENT_VALIDATE_UTF8=0 # Disable utf-8 validation
    ASIO_STANDALONE=1
    ASIO_NO_TYPEID=1
)

# --------------------------------------
add_executable(ex_binance_asio ex_binance_asio.cpp)
target_link_libraries(ex_binance_asio PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::ZLIBNG
    asio::asio
    websocketclient
)
target_compile_definitions(ex_binance_asio PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=0 # Use simdutf for utf-8 validation
    WS_CLIENT_VALIDATE_UTF8=0 # Disable utf-8 validation
    ASIO_STANDALONE=1
    ASIO_NO_TYPEID=1
)

# --------------------------------------
file(GLOB_RECURSE SOURCES "../include/*.cpp")
add_executable(ex_binance_coroio ex_binance_coroio.cpp ${SOURCES})
target_link_libraries(ex_binance_coroio PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::ZLIBNG
    websocketclient
)
target_compile_definitions(ex_binance_coroio PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=0 # Use simdutf for utf-8 validation
    WS_CLIENT_VALIDATE_UTF8=0 # Disable utf-8 validation
)

# # --------------------------------------
add_executable(ex_reconnect_asio ex_reconnect_asio.cpp)
target_link_libraries(ex_reconnect_asio PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    simdutf::simdutf
    asio::asio
    PkgConfig::ZLIBNG
    websocketclient
)
target_compile_definitions(ex_reconnect_asio PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=0 # Use simdutf for utf-8 validation
    WS_CLIENT_VALIDATE_UTF8=0 # Disable utf-8 validation
    ASIO_STANDALONE=1
    ASIO_NO_TYPEID=1
)
