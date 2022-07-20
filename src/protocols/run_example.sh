#!/bin/bash

# run 'chmod +x run_example.sh' to make this script executable

# opens 4 terminals and starts server for the local network
gnome-terminal -- cargo run --bin server 1 -l
gnome-terminal -- cargo run --bin server 2 -l
gnome-terminal -- cargo run --bin server 3 -l
gnome-terminal -- cargo run --bin server 4 -l