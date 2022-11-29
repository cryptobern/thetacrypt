# Threshold Cryptography Library in Rust

This is a WIP library for threshold cryptography implementing various threshold cipher, signatures and coin schemes. The library relies on Tendermint Core for atomic broadcast and runs as a service next to Tendermint on a node.

## Installation

You can download and install Rust on Linux using 

    curl https://sh.rustup.rs -sSf | sh

To run the schemes test application, use 

    cd src
    cargo run --release
