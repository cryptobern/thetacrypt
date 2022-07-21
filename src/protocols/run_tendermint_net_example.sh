#!/bin/bash

# run 'chmod +x run_tendermint_net_example.sh' to make this script executable

# opens 4 terminals and starts server for the local network
gnome-terminal -- docker exec -it node0 /bin/sh && cd threshold_crypto_app/protocols && cargo run --bin server 1
gnome-terminal -- docker exec -it node1 /bin/sh && cd threshold_crypto_app/protocols && cargo run --bin server 2
gnome-terminal -- docker exec -it node2 /bin/sh && cd threshold_crypto_app/protocols && cargo run --bin server 3
gnome-terminal -- docker exec -it node3 /bin/sh && cd threshold_crypto_app/protocols && cargo run --bin server 4
