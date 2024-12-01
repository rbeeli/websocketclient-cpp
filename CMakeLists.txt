cmake_minimum_required(VERSION 3.15)

# Set the C++ standard and related settings
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(websocketclient
    VERSION 0.3
    LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

add_library(${PROJECT_NAME} INTERFACE)

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

# Install header files
install(DIRECTORY include/ DESTINATION include)

# Export the library target
install(EXPORT ${PROJECT_NAME}Targets
    FILE ${PROJECT_NAME}Config.cmake
    NAMESPACE ${PROJECT_NAME}::
    DESTINATION lib/cmake/${PROJECT_NAME}
)

# Generate a package config file for find_package
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
    DESTINATION lib/cmake/${PROJECT_NAME}
)