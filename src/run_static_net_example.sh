#!/bin/bash

# run 'chmod +x run_static_net_example.sh' to make this script executable

# opens 4 terminals and starts server for the local network
gnome-terminal -- cargo run --bin server -- --config-file conf/server_0.json --key-file conf/keys_0.json
gnome-terminal -- cargo run --bin server -- --config-file conf/server_1.json --key-file conf/keys_1.json
gnome-terminal -- cargo run --bin server -- --config-file conf/server_2.json --key-file conf/keys_2.json
gnome-terminal -- cargo run --bin server -- --config-file conf/server_3.json --key-file conf/keys_3.json
