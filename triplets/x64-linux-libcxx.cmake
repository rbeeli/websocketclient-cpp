# Standard platform configuration.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)

# libc++ configuration
set(VCPKG_C_FLAGS "") # This must be set if VCPKG_CXX_FLAGS is.
set(VCPKG_CXX_FLAGS "-stdlib=libc++")
set(VCPKG_LINKER_FLAGS "-lc++ -lc++abi")
