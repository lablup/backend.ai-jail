#! /bin/bash

ARCHITECTURE=$(uname -m)
if [ $ARCHITECTURE = "arm64" ]; then
    ARCHITECTURE="aarch64"
fi
apt update && apt install -y libseccomp-dev

cd /io
cargo build --release
cp /io/target/release/backendai-jail /io/dist/backendai-jail.$PLATFORM.$ARCHITECTURE.bin
chown $FILEUSER /io/dist/backendai-jail.$PLATFORM.$ARCHITECTURE.bin
rm -r /io/target/release
