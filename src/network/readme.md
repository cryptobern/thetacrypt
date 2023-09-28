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

- The script `run_static_net_example.sh` in `src/protocols` can be executed in order to open four terminals and starting a server in each of them automatically.

# Interface for a *Tendermint* network

![Network interface](Interface_Tendermint_Net.png)

- Instead of keeping track of all the server IPs in a `config.toml` file we only list the port numbers for our P2P and RPC network, e.g. <br/>
`p2p_port = 27000` <br/>
`rpc_port = 50050` <br/>
and ask the local Tendermint RPC endpoint for the IPs of the other Tendermint nodes.

- The `init(...)` function for a network that runs with *Tendermint* only requires two channel endpoints, the one for receiving messages from the Protocols layer to broadcast to the P2P network and one to send the incoming messages to the Protocols layer.

- This setup assumes that our Threshold Crypto Library instances are running on the same full node (hence, are accessible through the same IP) as the Tendermint Core instances. The figure below illustrates a network of five full nodes where Tendermint Core and the Threshold Crypto Library instances are running together on every node.

![Network interface](Tendermint_TCL_Stack.png)

Currently, this setup is realized as follows:
- The code of the Threshold Crypto Library is placed into the `tendermint/build` directory, which will be mounted to the Docker containers.

- The `Dockerfile` in `tendermint/networks/local/localnode` has been extended in order to make the code of the Threshold Crypto Library executable inside the Docker containers. First, the version of `alpine` was updated (**FROM** `alpine:latest`). And second, the following lines were added to the **RUN** command: <br/>
`apk add --update alpine-sdk && \`<br/>
`apk --no-cache add rust cargo && \`<br/>
`apk --no-cache add libressl-dev && \`<br/>
`apk --no-cache add protoc`<br/>

- After launching the tendermint testnet (`make localnet-start`), you can log in manually into each Docker container (e.g. `docker exec -it node0 /bin/sh`) and run a server (e.g. `cargo run --bin server 1`). As soon as the servers are connected over the P2P network they are ready to receive client requests.

# About **libp2p**
We are using the Rust implementation of **libp2p** (https://github.com/libp2p/rust-libp2p), which is a modular peer-to-peer networking framework.

Learn more: https://docs.rs/libp2p/latest/libp2p/

# About **Floodsub** and **Gossipsub**
https://docs.libp2p.io/introduction/what-is-libp2p/: Sending messages to other peers is at the heart of most peer-to-peer systems, and pubsub (short for publish / subscribe) is a very useful pattern for sending a message to groups of interested receivers.</br>
**libp2p** defines a pubsub interface for sending messages to all peers subscribed to a given “topic”. The interface currently has two stable implementations:
- **Floodsub** uses a very simple but inefficient “network flooding” strategy, and
- **Gossipsub** defines an extensible gossip protocol.

Learn more:
- https://docs.libp2p.io/concepts/publish-subscribe/
- https://github.com/libp2p/specs/tree/master/pubsub
- https://github.com/libp2p/specs/tree/master/pubsub/gossipsub#implementation-status

This **Network layer** contains implementations of both libp2p protocols, but the currently provided interfaces (`init(...)`) implement the **Gossipsub** protocol for the P2P networking.

# About **Tokio** and **async_std**

Both are asynchronous runtimes for Rust that don't seem to differ much from each other. Since **Tokio** has a larger ecosystem than **async_std** we decided to use **Tokio** as asynchronous runtime.

Tokio:
- https://tokio.rs/
- https://tokio.rs/tokio/tutorial

async_std:
- https://crates.io/crates/async_std
- https://book.async.rs/



# Package structure

### **bin**:
Sandbox - code to test the modules (config, p2p) and examples (see "How to use").

### **config**:
Contains two sub-modules, one for a *static* network (`config/static_net`) and one for a network that runs with *tendermint* (`config/tendermint_net`). Each submodule contains a `config.toml`, a `config_service.rs` that provides functions to load and read the data from `config.toml` and a `deserialize.rs` containing the necessary structs to deserialize the contents of `config.toml`. <br/> The `config.toml` in `config/static_net` contains all IPs and port numbers from each server. The `config.toml` in `config/tendermint_net` on the other hand only contains the port numbers for the P2P and RPC endpoints. The IPs of the other servers are learned via RPC request `/net_info` at the local Tendermint instance, which is located in `config/tendermint_net/rpc_requests`.

### **p2p**:
This module contains two sub-modules, one for each implementation of the libp2p pubsub protocols:

- `gossipsub_setup`

    The sub-module `p2p/gossipsub_setup` contains the two interfaces for the Protocols layer, one for a *static* network (`static_net.rs`) and one for a network that runs with *Tendermint* (`tendermint_net.rs`). The interfaces differ in the way how the IPs and port numbers are retrieved for opening a listening port and for dialing the other servers. Hence, while the interface in `tendermint_net.rs` only requires the receiver of the **out-channel** (`out_msg_recv`) and the sender of the **in-channel** (`in_msg_send`) as input parameter, the interface in `static_net.rs` additionally requires the server's `id`.

    - `static_net.rs`
    With the given server's `id` the local port number can be retrieved from `config.toml` in order to open the P2P listener. Furthermore, using the server's `id` the port numbers of the other servers can be loaded from `config.toml` to establish the P2P network.

    - `tendermint_net.rs`
    In order to dial to the other servers their IPs are requested at the local Tendermint RPC endpoint.

    - `net_utils.rs`
    All common functionalities of `static_net.rs` and `tendermint_net.rs` are located here.


- `floodsub_setup`
    
    The public function `init(...)` in `setup.rs` can be used to send and receive messages to and from the network using the `Floodsub` protocol, the `Mdns` protocol (to automatically identify other peers in the *local* network) and the `tokio` runtime. The customized network-behaviour is defined in `floodsub_mdns_behaviour.rs`.

    The `init` function in `floodsub_tokio_setup.rs` requires the arguments `floodsub::topic` and the `UnboundedReceiver` from the **out-channel**, creates a tokio-based TCP transport, builds a swarm using a random peerId, opens a random listening port and kicks off the select-loop. There are two branches in the select-loop, one for broadcasting messages to the network populated by the `UnboundedReceiver` of the channel and one branch that handles SwarmEvents. Since there is a customized `NetworkBehaviour` defined (`p2p/floodsub/floodsub_mdns_behaviour.rs`), the handling of incoming messages is implemented in the sub-module **deliver**. Note that the function `handle_msg(&self)` is called in `p2p/floodsub/floodsub_mdns_behaviour.rs`. 

### **types**:
Contains the struct `NetMessage` along with two implementations to convert a `NetMessage` into a `Vec<u8>` and vice versa.
See `Types` below for more information.

### **lib.rs**:
Makes all modules accessible from outside and contains a single utility method to get the rust data type.


# Types


### `NetMessage`:

It is the abstraction of a message used in the network crate. It contains
three fields, which are all the network needs to know about a message:
- `instance_id`: The ID of the protocol instance the message is related to.
- `is_total_order`: A boolean that shows whether the message has been received / must be sent
in a total order way.
The following must be guaranteed by the network layer: Messages with `is_total_order == true` are
delivered in the same order by all Thetacrypt nodes (but might be interleaved with non total-order
messages).
- `message_data`: The payload of the message, of type `Vec<u8>`.


# network/src/bin: Demo / Test

- The code in `test_static_setup.rs` demonstrates how a client side of the Network layer creates the required parameters and call the `init(...)` function from the module `p2p/gossipsub_setup/static_net.rs` in a separate thread. <br/> To transmit messages to and from the network layer, two channels are created (**out-channel** and **in-channel**). Test messages to be sent to the network are created and added to the **out_channel** every 10 seconds. Incoming messages from the network are received via the **in-channel**.

- In `test_tendermint_setup.rs` the exact same thing is tested/demonstrated, here using the interface (`init(...)`) in `p2p/gossipsub_setup/tendermint_net.rs`.

<!-- All other files in `network/src/bin` can be used to test other components of the package, such as -->
- `test_floodsub_setup.rs` can be used to test the implementation of libp2p using the **Floodsub** protocol.

- The crate `tendermint_rpc` is tested in `test_tendermint_rpc.rs` but not currently used here, since it's not working yet as expected (see Slack).<br>


