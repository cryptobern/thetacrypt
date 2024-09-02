#!/bin/bash

# Check if the number of lines is provided as a parameter
if [ $# -ne 1 ]; then
    echo "Usage: $0 <num_lines>"
    exit 1
fi

num_lines=$1

threshold=$(echo "(($num_lines - 1) * 1/3) + 1 " | bc) 

# Purge previous config
rm -r conf/*

# Create the server_ips.txt file
ip_address="127.0.0.1"

for ((i=1; i<=$num_lines; i++))
do
    echo "$ip_address"
done > conf/server_ips.txt


# Generate the configuration files
cargo run --bin confgen -- --ip-file conf/server_ips.txt --port-strategy consecutive --outdir=conf

# Generate the keystore files 
cargo run --bin thetacli -- keygen -k=${threshold} -n=${num_lines} --subjects Frost-Ed25519 --output ./conf


# Create the start_network.sh file
cat > start_network.sh <<EOF
#!/bin/bash

EOF

for ((i=1; i<=$num_lines; i++))
do
    echo "cargo run --bin server -- --config-file conf/server_${i}.json --key-file conf/node${i}.keystore &" >> start_network.sh
done

echo "wait" >> start_network.sh

echo "pids=\$(jobs -p)" >> start_network.sh

echo "kill \$pids" >> start_network.sh

chmod +x start_network.sh