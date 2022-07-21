# The network layer

Two interfaces are provided: one for a *static* network and one for a network that uses *Tendermint* in order to get the IP addresses of the other peers.

# Interface for a *static* network

![Network interface](Interface_Static_Net.png)

- *static* means that all the IPs and port numbers are given in `config.toml`, e.g. <br/>
`ids = [1, 2, 3, 4]`<br/>
`ips = ["127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"]`<br/>
`p2p_ports = [27001, 27002, 27003, 27004]`<br/>
`rpc_ports = [50051, 50052, 50053, 50054]`<br/>
- The `init(...)` function for a *static* network requires two channel endpoints, one for receiving messages from the Protocols layer to broadcast to the P2P network and one to send the incoming messages to the Protocols layer. Additionally, the server's id is required in order to load the correct IPs and port numbers from `config.toml`.
- When running a server in a *static* network provide the `-l` flag, e.g. <br/>
`cargo run --bin server 1 -l`<br/>
- There is a script `run_static_net_example.sh` in `src/protocols` which opens four terminals and starts a server in each of them.

# Interface for a *Tendermint* network

![Network interface](Interface_Tendermint_Net.png)

- Instead of keeping track of all the server IPs in a `config.toml` file we only keep the port number for our P2P and RPC network, e.g. <br/>
`p2p_port = 27000` <br/>
`rpc_port = 50050` <br/>
and ask the local Tendermint RPC endpoint for the IPs of the other Tendermint nodes.
- The `init(...)` function for a network that runs with *Tendermint* only requires two channel endpoints, the one for receiving messages from the Protocols layer to broadcast to the P2P network and one to send the incoming messages to the Protocols layer.

- This setup assumes that our Threshold Crypto Library instances are running on the same full node (hence, are accessible through the same IP) as the Tendermint Core instances. The figure below illustrates a network of five full nodes where Tendermint Core and the Threshold Crypto Library instances are running together on every node.

![Network interface](Tendermint_TCL_Stack.png)