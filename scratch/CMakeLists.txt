find_package(asio CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(simdutf CONFIG REQUIRED)
find_package(ZLIB REQUIRED)

# --------------------------------------

add_executable(test_asio_http test_asio_http.cpp)
target_link_libraries(test_asio_http PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    simdutf::simdutf
    asio::asio
    websocketclient)
target_compile_definitions(test_asio_http PRIVATE
    ASIO_STANDALONE=1
    ASIO_NO_TYPEID=1)

# --------------------------------------

add_executable(test_openssl test_openssl.cpp)
target_link_libraries(test_openssl PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# --------------------------------------

# file(GLOB_RECURSE SOURCES_COROIO "../coroio/*.cpp")
# add_executable(test_coroio_bench test_coroio_bench.cpp ${SOURCES_COROIO})
# target_include_directories(test_coroio_bench PRIVATE "../")
# target_link_libraries(test_coroio_bench PRIVATE
#     OpenSSL::SSL
#     OpenSSL::Crypto
#     ZLIB::ZLIB
#     simdutf::simdutf
#     websocketclient)

# --------------------------------------
