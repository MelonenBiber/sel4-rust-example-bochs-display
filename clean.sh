# Get directory of clean.sh (project root)
ROOT="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# Clean seL4 and rust builds but not the dependencies (they take kind of a long time to build)
rm -rf $ROOT/seL4/build
rm -rf $ROOT/seL4/install
rm -rf $ROOT/target/out

# Blank slate
if [ "$1" = "all" ]; then
pushd $ROOT
    cargo clean
popd
fi
