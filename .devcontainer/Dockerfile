# [Choice] Debian / Ubuntu version (use Debian 12, Debian 11, Ubuntu 22.04 on local arm64/Apple Silicon): debian-12, debian-11, debian-10, ubuntu-22.04, ubuntu-20.04
ARG VARIANT=debian-12
FROM mcr.microsoft.com/devcontainers/base:${VARIANT}
USER root

# This Dockerfile's base image has a non-root user with sudo access. Use the "remoteUser"
# property in devcontainer.json to use it. On Linux, the container user's GID/UIDs
# will be updated to match your local UID/GID (when using the dockerFile property).
# See https://aka.ms/vscode-remote/containers/non-root-user for details.
# ARG USERNAME=vscode
# ARG USER_UID=1000
# ARG USER_GID=$USER_UID

ENV VCPKG_ROOT /usr/vcpkg
ENV VCPKG_FORCE_SYSTEM_BINARIES 1
ENV VCPKG_MANIFEST_MODE 1

# Configure apt and install packages
RUN apt-get update \
    && export DEBIAN_FRONTEND=noninteractive \
    #
    # Install C++ tools and Git
    && apt-get -y install build-essential gdb cmake cppcheck valgrind git zip unzip ninja-build pkg-config linux-libc-dev \
    # install python 3
    && apt-get -y install python3 python3-pip python3-venv \
    #
    # [Optional] Update UID/GID if needed
    # && if [ "$USER_GID" != "1000" ] || [ "$USER_UID" != "1000" ]; then \
    # groupmod --gid $USER_GID $USERNAME \
    # && usermod --uid $USER_UID --gid $USER_GID $USERNAME \
    # && chown -R $USER_UID:$USER_GID /home/$USERNAME; \
    # fi \
    #
    # Clean up
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Install vcpkg dependency manager
RUN git clone https://github.com/Microsoft/vcpkg ${VCPKG_ROOT} \
    && cd ${VCPKG_ROOT} \
#     # This is (for now) the way vcpkg handles versioning: freezing the cloned repo at a specific commit!
#     # See https://github.com/microsoft/vcpkg/issues/1681.
#     && git reset --hard 077c0746be3773fdd443af52cbe5c3cc26379a15 \
    && ./bootstrap-vcpkg.sh

ENV PATH "${VCPKG_ROOT}:${PATH}"

# Install C++ dependencies using vcpkg
RUN vcpkg integrate install
