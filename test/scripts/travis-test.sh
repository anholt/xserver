#!/bin/sh

# This is a separate script from .travis.yml, because it's being run
# inside of the docker image (the Travis environment doesn't carry
# over inside the docker run command).

export PREFIX=/usr
export TRAVIS_BUILD_DIR=/root
export PIGLIT_DIR=$TRAVIS_BUILD_DIR/piglit
export XTEST_DIR=$TRAVIS_BUILD_DIR/xtest

set -e

meson build/
ninja -C build/ install
ninja -C build/ test
