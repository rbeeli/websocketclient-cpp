find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(simdutf CONFIG REQUIRED)
find_package(asio CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(ZLIBNG REQUIRED IMPORTED_TARGET zlib-ng)

# --------------------------------------

add_executable(autobahn_builtin_zlib_utf8_naive autobahn_builtin.cpp) # ${SOURCES})
target_link_libraries(autobahn_builtin_zlib_utf8_naive PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    simdutf::simdutf
    websocketclient)
target_compile_definitions(autobahn_builtin_zlib_utf8_naive PRIVATE
    WS_CLIENT_USE_SIMD_UTF8=0 # disable simdutf for utf-8 validation
    WS_AUTOBAHN_AGENT_NAME="sync_zlib_utf8_naive"
)

add_executable(autobahn_builtin_zlib_ng_utf_simd autobahn_builtin.cpp) # ${SOURCES})
target_link_libraries(autobahn_builtin_zlib_ng_utf_simd PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::ZLIBNG
    simdutf::simdutf
    websocketclient)
target_compile_definitions(autobahn_builtin_zlib_ng_utf_simd PRIVATE
    WS_CLIENT_USE_ZLIB_NG=1 # use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=1 # use simdutf for utf-8 validation
    WS_AUTOBAHN_AGENT_NAME="sync_zlib_ng_utf_simd"
)

# --------------------------------------

add_executable(autobahn_asio_zlib_ng_utf_simd autobahn_asio.cpp ${SOURCES})
target_link_libraries(autobahn_asio_zlib_ng_utf_simd PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::ZLIBNG
    simdutf::simdutf
    asio::asio
    websocketclient)
target_compile_definitions(autobahn_asio_zlib_ng_utf_simd PRIVATE
    ASIO_STANDALONE=1
    ASIO_NO_TYPEID=1
    WS_CLIENT_USE_ZLIB_NG=1 # use zlib-ng instead of zlib
    WS_CLIENT_USE_SIMD_UTF8=1 # use simdutf for utf-8 validation
    WS_AUTOBAHN_AGENT_NAME="asio_zlib_ng_utf_simd"
)

# --------------------------------------

# file(GLOB_RECURSE SOURCES "../../include/*.cpp")
# add_executable(autobahn_coroio autobahn_coroio.cpp ${SOURCES})
# target_link_libraries(autobahn_coroio PRIVATE
# OpenSSL::SSL
# OpenSSL::Crypto
# ZLIB::ZLIB
# simdutf::simdutf
# websocketclient)

# --------------------------------------
