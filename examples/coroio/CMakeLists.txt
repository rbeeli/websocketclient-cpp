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
file(GLOB_RECURSE SOURCES "../../coroio/*.cpp")
add_executable(ex_binance_coroio ex_binance_coroio.cpp ${SOURCES})
target_link_libraries(ex_binance_coroio PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::ZLIBNG
    coroio
    websocketclient
)
target_compile_definitions(ex_binance_coroio PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # Use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=0 # Use simdutf for utf-8 validation
    WS_CLIENT_VALIDATE_UTF8=0 # Disable utf-8 validation
)
