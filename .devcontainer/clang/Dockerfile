FROM mcr.microsoft.com/devcontainers/cpp:dev-ubuntu-24.04

USER root

ENV VCPKG_FORCE_SYSTEM_BINARIES 1
ENV VCPKG_MANIFEST_MODE 1

# Configure apt and install packages
RUN apt-get update \
    && export DEBIAN_FRONTEND=noninteractive \
    #
    # Install Clang and related tools
    && apt-get -y install clang clang-format clang-tidy lld \
    && apt-get -y install libc++-dev libc++abi-dev \
    #
    # Install other C++ tools and Git
    && apt-get -y install cmake cppcheck valgrind git zip unzip ninja-build pkg-config linux-libc-dev \
    #
    # Install Python 3
    && apt-get -y install python3 python3-pip python3-venv \
    #
    # Clean up
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Install C++ dependencies using vcpkg
RUN vcpkg integrate install

# Set Clang as the default compiler
ENV CC=/usr/bin/clang
ENV CXX=/usr/bin/clang++
