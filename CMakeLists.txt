cmake_minimum_required(VERSION 3.21)

# Set the C++ standard and related settings
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(websocketclient
    VERSION 0.7.7
    LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

find_package(ZLIB REQUIRED)

add_library(${PROJECT_NAME} INTERFACE)
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_23)

target_link_libraries(${PROJECT_NAME} INTERFACE ZLIB::ZLIB)

target_include_directories(${PROJECT_NAME} INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

option(WS_CLIENT_BUILD_EXAMPLES "Build example programs in ./examples directory" OFF)
option(WS_CLIENT_BUILD_TESTS "Build tests in ./test directory" OFF)
option(WS_CLIENT_BUILD_BENCH "Build benchmarks programs in ./bench directory" OFF)
option(WS_CLIENT_BUILD_SCRATCH "Build scratch programs in ./scratch directory" OFF)

# ./examples
if(WS_CLIENT_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ./tests
if(WS_CLIENT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ./bench
if(WS_CLIENT_BUILD_BENCH)
    add_subdirectory(bench)
endif()

# ./scratch
if(WS_CLIENT_BUILD_SCRATCH)
    add_subdirectory(scratch)
endif()

# --------------------------------------------------
# Install
# --------------------------------------------------

# Install the library
install(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}Targets
)

# Install header files, excluding the unfinished Coroio transport adapter.
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    PATTERN "CoroioSocket.hpp" EXCLUDE
)

# Generate package configuration files
configure_package_config_file(
    cmake/${PROJECT_NAME}Config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

install(EXPORT ${PROJECT_NAME}Targets
    FILE ${PROJECT_NAME}Targets.cmake
    NAMESPACE ${PROJECT_NAME}::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)
