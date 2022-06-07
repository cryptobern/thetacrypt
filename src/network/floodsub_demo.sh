#! /bin/sh

# gnome-terminal -x  bash -c "echo foo; sleep 3; echo  bar; sleep 3"

gnome-terminal --tab --title="1" -e "bash -c 'cargo run --bin broadcast_floodsub'" &
gnome-terminal --tab --title="2" -e "bash -c 'cargo run --bin broadcast_floodsub'"


