# Package structure

- **bin**: sandbox - code to test the modules (channel, network_info, p2p) and examples (see "How to use").

- **config**: contains a `config.toml` with all ids, ips, p2p_ports, rpc_ports of the network servers and the local listener address. <br/> The function `load_config(path)` is provided in `deserialize.rs` along with the necessary structs to deserialize the contents from the `config.toml` file.

- **network_info**: this module contains requests to a Tendermint RPC endpoint in `rpc_net_info.rs` and `rpc_status.rs` (https://docs.tendermint.com/v0.35/rpc/) which return the `Result`s of the corresponding request. All structs to deserialize the JSON-RPC responses from Tendermint can be found in `deserialize.rs`. A conversion of the addresses wrapped in the `Result` into a libp2p `Multiaddr` format can be done with the functions provided in `address_converter.rs` (*warning*: room for improvement!).

- **p2p**: This module contains two sub-modules, one for each implementation of the libp2p pubsub protocols:

    ```gossipsub```
    
    The public function `init(...)` in `setup.rs` is the interface to send and receive messages to and from the network using the `Gossipsub` protocol and the `Tokio` runtime.

    The `init(...)` function requires a `GossipsubTopic`, the receiver of the **out-channel** (`chn_out_recv`) and the sender of the **in-channel** (`chn_in_send`).
    
    Using a randomly created `KeyPair` and `PeerId` a tokio-based TCP transport and a swarm are created, the listening port is openend and another peer in the network is dialed. Finally, the `select!`-loop is kicked off, which contains one branch for sending messages to the network (received through the internal **out-channel**) and one branch for handling the `SwarmEvent`s, such as the incoming `GossibsubEvent::Message`. These messages are added to the internal **in-channel** and can be consumed with the corresponding receiver.

    ```floodsub```
    
    The public function `init(...)` in `setup.rs` can be used to send and receive messages to and from the network using the `Floodsub` protocol, the `Mdns` protocol (to automatically identify other peers in the *local* network) and the `tokio` runtime. The customized network-behaviour is defined in `floodsub_mdns_behaviour.rs`.

    The `init` function in `floodsub_tokio_setup.rs` requires the arguments `floodsub::topic` and the `UnboundedReceiver` from the **out-channel**, creates a tokio-based TCP transport, builds a swarm using a random peerId, opens a random listening port and kicks off the select-loop. There are two branches in the select-loop, one for broadcasting messages to the network populated by the `UnboundedReceiver` of the channel and one branch that handles SwarmEvents. Since there is a customized `NetworkBehaviour` defined (`p2p/floodsub/floodsub_mdns_behaviour.rs`), the handling of incoming messages is implemented in the sub-module **deliver**. Note that the function `handle_msg(&self)` is called in `p2p/floodsub/floodsub_mdns_behaviour.rs`. 

- **types**: contains the struct `P2pMessage` along with two implementations to convert a `P2pMessage` into a `Vec<u8>` and the other way around.

- **lib.rs**: makes all modules accessible from outside and contains a single utility method to get the rust data type.

# How to use / Examples: network/src/bin
Some files in `network/src/bin` contain test code to simulate the usage of the network interface or examples from libp2p's example collection (https://github.com/libp2p/rust-libp2p/tree/master/examples):

<!-- Since we are focussing on the libp2p implementation of the **Gossipsub** protocol (https://github.com/libp2p/specs/tree/master/pubsub/gossipsub#implementation-status) and the crate **Tokio**, an asynchronous runtime for Rust (https://tokio.rs/), the most relevant file is `test_gossipsub_setup.rs`: -->
- The code in `test_gossipsub_setup.rs` shows how the client side of the network creates the required parameters and call the `init(...)` function from the module `p2p/gossipsub/setup.rs` in a separate thread.
To transmit messages to and from the network layer, two channels have to be created by the client, let's call them **out-channel** and **in-channel**. Messages to be broadcasted to the network are then added to the **out-channel** and incoming messages from the network are received through the **in-channel**.

<!-- All other files in `network/src/bin` can be used to test other components of the package, such as -->
- `test_floodsub_setup.rs` can be used to test the implementation of libp2p using the **Floodsub** protocol.

- The RPC-requests on a Tendermint node can be tested with `test_tendermint_req.rs` or `test_tendermint_rpc.rs` (not working yet).<br>

- The files `broadcast_floodsub.rs` and `broadcast_gossipsub.rs` mostly contain libp2p's example code of `chat-tokio.rs` and `gossipsub-chat.rs` from https://github.com/libp2p/rust-libp2p/tree/master/examples which implement a chat tool (messages typed into the cli of one peer are broadcasted to all other peers in the network). The implementations differ in the underlying protocols and runtimes: While `broadcast_floodsub.rs`/`chat-tokio.rs` use the **Floodsub** protocol to broadcast messages (and the **Mdns** protocol to automatically identify peers in the network) and the asynchronous **Tokio** runtime (https://tokio.rs/tokio/tutorial), `broadcast_gossipsub.rs`/`gossipsub-chat.rs` use the **Gossipsub** protocol for the broadcast and **async-std**, an asynchronous version of the Rust standard library (https://crates.io/crates/async_std). See more about the different protocols below.<br/>

- An implementation of the **Gossipsub** protocol together with the **Tokio** runtime is realized in `broadcast_gossipsub_tokio.rs`.

# About **Floodsub** and **Gossipsub**
https://docs.libp2p.io/introduction/what-is-libp2p/: Sending messages to other peers is at the heart of most peer-to-peer systems, and pubsub (short for publish / subscribe) is a very useful pattern for sending a message to groups of interested receivers.</br>
**libp2p** defines a pubsub interface for sending messages to all peers subscribed to a given “topic”. The interface currently has two stable implementations:
- **Floodsub** uses a very simple but inefficient “network flooding” strategy, and
- **Gossipsub** defines an extensible gossip protocol.

More:
- https://docs.libp2p.io/concepts/publish-subscribe/
- https://github.com/libp2p/specs/tree/master/pubsub
- https://github.com/libp2p/specs/tree/master/pubsub/gossipsub#implementation-status

# About **Tokio** and **async_std**

Both are asynchronous runtimes for Rust that don't seem to differ much from each other. Since **Tokio** has a larger ecosystem than **async_std** it's reasonable to go with this runtime.

Tokio:
- https://tokio.rs/
- https://tokio.rs/tokio/tutorial

async_std:
- https://crates.io/crates/async_std
- https://book.async.rs/
