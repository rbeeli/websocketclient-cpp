#!/bin/sh

cmake --preset dev_install
cmake --build --preset dev_install
cmake --install out/dev_install --config Release
