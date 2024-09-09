# copy cert.pem public key to build directory
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/certs/cert.pem
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(asio)
add_subdirectory(builtin)
# add_subdirectory(coroio)
