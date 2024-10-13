find_package(asio CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(simdutf CONFIG REQUIRED)
find_package(ZLIB REQUIRED)

# --------------------------------------

add_executable(scratch_asio_http asio_http.cpp)
target_link_libraries(scratch_asio_http PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    simdutf::simdutf
    asio::asio
    websocketclient)
target_compile_definitions(scratch_asio_http PRIVATE
    ASIO_STANDALONE=1
    ASIO_NO_TYPEID=1)

# --------------------------------------

add_executable(scratch_asio_seq_strand asio_seq_strand.cpp)
target_link_libraries(scratch_asio_seq_strand PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    asio::asio)
target_compile_definitions(scratch_asio_seq_strand PRIVATE
    ASIO_STANDALONE=1
    ASIO_NO_TYPEID=1)

# --------------------------------------

add_executable(scratch_openssl openssl.cpp)
target_link_libraries(scratch_openssl PRIVATE OpenSSL::SSL OpenSSL::Crypto)


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
