add_subdirectory(autobahn)

# file(GLOB_RECURSE SOURCES "../include/*.cpp")

# copy cert.pem public key to build directory
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/certs/cert.pem
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

find_package(GTest CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(asio CONFIG REQUIRED)

enable_testing()

file(GLOB_RECURSE SOURCES_TESTS "./impl/*.cpp")
add_executable(unit_tests ${SOURCES_TESTS})

include(GoogleTest)
gtest_discover_tests(unit_tests)

target_link_libraries(unit_tests PRIVATE
    GTest::gtest_main
    GTest::gtest
    ZLIB::ZLIB
    OpenSSL::SSL
    OpenSSL::Crypto
    websocketclient
)

# test_close_AsioSocket
add_executable(test_close_AsioSocket "./test_close_AsioSocket.cpp")
# gtest_discover_tests(test_close_AsioSocket)
target_link_libraries(test_close_AsioSocket PRIVATE
    GTest::gtest_main
    GTest::gtest
    ZLIB::ZLIB
    OpenSSL::SSL
    OpenSSL::Crypto
    asio::asio
    websocketclient
)
target_compile_definitions(test_close_AsioSocket PRIVATE
    ASIO_STANDALONE=1
    ASIO_NO_TYPEID=1
)

# test_close_OpenSslSocket
add_executable(test_close_OpenSslSocket "./test_close_OpenSslSocket.cpp")
# gtest_discover_tests(test_close_OpenSslSocket)
target_link_libraries(test_close_OpenSslSocket PRIVATE
    GTest::gtest_main
    GTest::gtest
    ZLIB::ZLIB
    OpenSSL::SSL
    OpenSSL::Crypto
    websocketclient
)
