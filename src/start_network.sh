#!/bin/bash

cargo run --bin server -- --config-file conf/server_1.json --key-file conf/node1.keystore &
cargo run --bin server -- --config-file conf/server_2.json --key-file conf/node2.keystore &
cargo run --bin server -- --config-file conf/server_3.json --key-file conf/node3.keystore &
cargo run --bin server -- --config-file conf/server_4.json --key-file conf/node4.keystore &
cargo run --bin server -- --config-file conf/server_5.json --key-file conf/node5.keystore &
cargo run --bin server -- --config-file conf/server_6.json --key-file conf/node6.keystore &
cargo run --bin server -- --config-file conf/server_7.json --key-file conf/node7.keystore &
cargo run --bin server -- --config-file conf/server_8.json --key-file conf/node8.keystore &
cargo run --bin server -- --config-file conf/server_9.json --key-file conf/node9.keystore &
cargo run --bin server -- --config-file conf/server_10.json --key-file conf/node10.keystore &
cargo run --bin server -- --config-file conf/server_11.json --key-file conf/node11.keystore &
cargo run --bin server -- --config-file conf/server_12.json --key-file conf/node12.keystore &
cargo run --bin server -- --config-file conf/server_13.json --key-file conf/node13.keystore &
cargo run --bin server -- --config-file conf/server_14.json --key-file conf/node14.keystore &
cargo run --bin server -- --config-file conf/server_15.json --key-file conf/node15.keystore &
cargo run --bin server -- --config-file conf/server_16.json --key-file conf/node16.keystore &
cargo run --bin server -- --config-file conf/server_17.json --key-file conf/node17.keystore &
cargo run --bin server -- --config-file conf/server_18.json --key-file conf/node18.keystore &
cargo run --bin server -- --config-file conf/server_19.json --key-file conf/node19.keystore &
cargo run --bin server -- --config-file conf/server_20.json --key-file conf/node20.keystore &
cargo run --bin server -- --config-file conf/server_21.json --key-file conf/node21.keystore &
cargo run --bin server -- --config-file conf/server_22.json --key-file conf/node22.keystore &
cargo run --bin server -- --config-file conf/server_23.json --key-file conf/node23.keystore &
cargo run --bin server -- --config-file conf/server_24.json --key-file conf/node24.keystore &
cargo run --bin server -- --config-file conf/server_25.json --key-file conf/node25.keystore &
cargo run --bin server -- --config-file conf/server_26.json --key-file conf/node26.keystore &
cargo run --bin server -- --config-file conf/server_27.json --key-file conf/node27.keystore &
cargo run --bin server -- --config-file conf/server_28.json --key-file conf/node28.keystore &
cargo run --bin server -- --config-file conf/server_29.json --key-file conf/node29.keystore &
cargo run --bin server -- --config-file conf/server_30.json --key-file conf/node30.keystore &
cargo run --bin server -- --config-file conf/server_31.json --key-file conf/node31.keystore &
cargo run --bin server -- --config-file conf/server_32.json --key-file conf/node32.keystore &
cargo run --bin server -- --config-file conf/server_33.json --key-file conf/node33.keystore &
cargo run --bin server -- --config-file conf/server_34.json --key-file conf/node34.keystore &
cargo run --bin server -- --config-file conf/server_35.json --key-file conf/node35.keystore &
cargo run --bin server -- --config-file conf/server_36.json --key-file conf/node36.keystore &
cargo run --bin server -- --config-file conf/server_37.json --key-file conf/node37.keystore &
cargo run --bin server -- --config-file conf/server_38.json --key-file conf/node38.keystore &
cargo run --bin server -- --config-file conf/server_39.json --key-file conf/node39.keystore &
cargo run --bin server -- --config-file conf/server_40.json --key-file conf/node40.keystore &
cargo run --bin server -- --config-file conf/server_41.json --key-file conf/node41.keystore &
cargo run --bin server -- --config-file conf/server_42.json --key-file conf/node42.keystore &
cargo run --bin server -- --config-file conf/server_43.json --key-file conf/node43.keystore &
cargo run --bin server -- --config-file conf/server_44.json --key-file conf/node44.keystore &
cargo run --bin server -- --config-file conf/server_45.json --key-file conf/node45.keystore &
cargo run --bin server -- --config-file conf/server_46.json --key-file conf/node46.keystore &
cargo run --bin server -- --config-file conf/server_47.json --key-file conf/node47.keystore &
cargo run --bin server -- --config-file conf/server_48.json --key-file conf/node48.keystore &
cargo run --bin server -- --config-file conf/server_49.json --key-file conf/node49.keystore &
cargo run --bin server -- --config-file conf/server_50.json --key-file conf/node50.keystore &
cargo run --bin server -- --config-file conf/server_51.json --key-file conf/node51.keystore &
cargo run --bin server -- --config-file conf/server_52.json --key-file conf/node52.keystore &
cargo run --bin server -- --config-file conf/server_53.json --key-file conf/node53.keystore &
cargo run --bin server -- --config-file conf/server_54.json --key-file conf/node54.keystore &
cargo run --bin server -- --config-file conf/server_55.json --key-file conf/node55.keystore &
cargo run --bin server -- --config-file conf/server_56.json --key-file conf/node56.keystore &
cargo run --bin server -- --config-file conf/server_57.json --key-file conf/node57.keystore &
cargo run --bin server -- --config-file conf/server_58.json --key-file conf/node58.keystore &
cargo run --bin server -- --config-file conf/server_59.json --key-file conf/node59.keystore &
cargo run --bin server -- --config-file conf/server_60.json --key-file conf/node60.keystore &
cargo run --bin server -- --config-file conf/server_61.json --key-file conf/node61.keystore &
cargo run --bin server -- --config-file conf/server_62.json --key-file conf/node62.keystore &
cargo run --bin server -- --config-file conf/server_63.json --key-file conf/node63.keystore &
cargo run --bin server -- --config-file conf/server_64.json --key-file conf/node64.keystore &
wait
pids=$(jobs -p)
kill $pids
