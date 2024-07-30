#!/bin/sh

cmake --preset gcc_dev_install
cmake --build --preset gcc_dev_install
cmake --install build/gcc/dev_install --config Release