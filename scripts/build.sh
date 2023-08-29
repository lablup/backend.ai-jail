#! /bin/bash

export CARGO_HOME=$(mktemp -d)
export RUSTUP_HOME=$(mktemp -d)

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
PATH="$HOME/.cargo/bin:$PATH"

ARCHITECTURE=$(uname -m)
cargo build --release
cp /io/target/release/backendai-jail /io/dist/backendai-jail.$PLATFORM.$ARCHITECTURE.bin