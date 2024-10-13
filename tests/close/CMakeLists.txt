# copy cert.pem public key to build directory
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/../certs/cert.pem
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(asio CONFIG REQUIRED)


# --------------------------------------
add_executable(test_close_server_asio "./test_close_server_asio.cpp")
target_link_libraries(test_close_server_asio PRIVATE
    ZLIB::ZLIB
    OpenSSL::SSL
    OpenSSL::Crypto
    asio::asio
    websocketclient
)
target_compile_definitions(test_close_server_asio PRIVATE
    ASIO_STANDALONE=1
    ASIO_NO_TYPEID=1
    WS_CLIENT_LOG_TCP=4
    WS_CLIENT_LOG_SSL=4
    WS_CLIENT_LOG_SEND_FRAME=4
    WS_CLIENT_LOG_RECV_FRAME=4
)

# --------------------------------------
add_executable(test_close_server_builtin_ssl "./test_close_server_builtin_ssl.cpp")
target_link_libraries(test_close_server_builtin_ssl PRIVATE
    ZLIB::ZLIB
    OpenSSL::SSL
    OpenSSL::Crypto
    websocketclient
)
target_compile_definitions(test_close_server_builtin_ssl PRIVATE
    WS_CLIENT_LOG_TCP=4
    WS_CLIENT_LOG_SSL=4
    WS_CLIENT_LOG_SEND_FRAME=4
    WS_CLIENT_LOG_RECV_FRAME=4
)

# --------------------------------------
