find_package(asio CONFIG REQUIRED)
find_package(wolfssl CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(simdutf CONFIG REQUIRED)
find_package(ZLIB REQUIRED)

add_executable(test_wolfssl test_wolfssl.cpp)
target_link_libraries(test_wolfssl PRIVATE wolfssl::wolfssl)

add_executable(test_openssl test_openssl.cpp)
target_link_libraries(test_openssl PRIVATE OpenSSL::SSL OpenSSL::Crypto)


file(GLOB_RECURSE SOURCES "../include/*.cpp")

add_executable(test_coroio_bench test_coroio_bench.cpp ${SOURCES})
target_include_directories(test_coroio_bench PRIVATE "../include/")
target_link_libraries(test_coroio_bench PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(test_coroio_bench PRIVATE ZLIB::ZLIB)
target_link_libraries(test_coroio_bench PRIVATE simdutf::simdutf)

add_executable(test_coroio_http test_coroio_http.cpp ${SOURCES})
target_include_directories(test_coroio_http PRIVATE "../include/")
target_link_libraries(test_coroio_http PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(test_coroio_http PRIVATE ZLIB::ZLIB)
target_link_libraries(test_coroio_http PRIVATE simdutf::simdutf)

add_executable(test_coroio_ws_client test_coroio_ws_client.cpp ${SOURCES})
target_include_directories(test_coroio_ws_client PRIVATE "../include/")
target_link_libraries(test_coroio_ws_client PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(test_coroio_ws_client PRIVATE ZLIB::ZLIB)
target_link_libraries(test_coroio_ws_client PRIVATE simdutf::simdutf)

add_executable(test_coroio_resolver test_coroio_resolver.cpp ${SOURCES})
target_include_directories(test_coroio_resolver PRIVATE "../include/")
target_link_libraries(test_coroio_resolver PRIVATE OpenSSL::SSL OpenSSL::Crypto)



add_executable(test_asio_ws_client test_asio_ws_client.cpp ${SOURCES})
target_include_directories(test_asio_ws_client PRIVATE "../include/")
target_link_libraries(test_asio_ws_client PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(test_asio_ws_client PRIVATE ZLIB::ZLIB)
target_link_libraries(test_asio_ws_client PRIVATE simdutf::simdutf)
target_link_libraries(test_asio_ws_client PRIVATE asio::asio)


file(GLOB_RECURSE SOURCES "../include/ws_client/*.cpp")
add_executable(test_asio_http test_asio_http.cpp ${SOURCES})
target_include_directories(test_asio_http PRIVATE "../include/")
target_link_libraries(test_asio_http PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(test_asio_http PRIVATE ZLIB::ZLIB)
target_link_libraries(test_asio_http PRIVATE simdutf::simdutf)
target_link_libraries(test_asio_http PRIVATE asio::asio)


add_executable(test_getaddrinfo_a test_getaddrinfo_a.cpp)

add_executable(test_DnsResolver test_DnsResolver.cpp)
target_include_directories(test_DnsResolver PRIVATE "../include/")



# include(FetchContent)

# set(PHOTON_ENABLE_URING OFF CACHE INTERNAL "Enable iouring")
# set(PHOTON_CXX_STANDARD 23 CACHE INTERNAL "C++ standard")

# FetchContent_Declare(
#     photon
#     GIT_REPOSITORY https://github.com/alibaba/PhotonLibOS.git
#     GIT_TAG release/0.7
# )
# FetchContent_MakeAvailable(photon)

# add_executable(test_photon_http test_photon_http.cpp ${SOURCES})
# target_include_directories(test_photon_http PRIVATE "../include/")
# target_link_libraries(test_photon_http PRIVATE
#     OpenSSL::SSL
#     OpenSSL::Crypto
#     ZLIB::ZLIB
#     simdutf::simdutf
#     photon_static)
