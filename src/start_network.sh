#!/bin/sh

cargo run --bin server -- --config-file conf/server_0.json --key-file conf/keys_0.json & 
cargo run --bin server -- --config-file conf/server_1.json --key-file conf/keys_1.json & 
cargo run --bin server -- --config-file conf/server_2.json --key-file conf/keys_2.json & 
cargo run --bin server -- --config-file conf/server_3.json --key-file conf/keys_3.json &
wait
