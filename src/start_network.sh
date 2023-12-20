#!/bin/sh

cargo run --bin server -- --config-file conf/server_0.json --key-file conf/node0.keystore & 
cargo run --bin server -- --config-file conf/server_1.json --key-file conf/node1.keystore & 
cargo run --bin server -- --config-file conf/server_2.json --key-file conf/node2.keystore & 
cargo run --bin server -- --config-file conf/server_3.json --key-file conf/node3.keystore &
wait
