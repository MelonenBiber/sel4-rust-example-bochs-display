#!/bin/bash

# Look at .cargo/config.toml for other important settings

set -e
# Get directory where this build script resides (project root)
ROOT="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# Useful directories
SEL4="$ROOT/seL4";
OUT="$ROOT/target/out" # same as artifact-dir in .cargo/config.toml
mkdir -p $OUT

# Optional build options
RELEASE=""
if [ "$1" = "release" ]; then
    RELEASE="--release"
fi


# Build the seL4 kernel if build directories dont exist
if [ ! -d "$SEL4/install" ] || [ ! -d "$SEL4/build" ]; then
pushd "$SEL4" >/dev/null
    echo "Building seL4"

    cmake -DCROSS_COMPILER_PREFIX=x86_64-linux-gnu- \
        -DCMAKE_INSTALL_PREFIX=install \
        -C ../kernel-settings.cmake \
        -G Ninja \
        -B build

    ninja -C build all
    ninja -C build install

    cp build/kernel.elf $OUT
    objcopy -O elf32-i386 $OUT/kernel.elf $OUT/kernel32.elf
popd >/dev/null
fi

# Build the damn thing
echo "Building project"
cargo build $RELEASE

