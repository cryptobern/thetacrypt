# Structure

- **bin**: sandbox - code to test the modules (deliver, network_info, send, setup) and examples (see below).
- **deliver**: in this module you can find the trait `HandleMsg` including the function `handle_msg(&self)` which can be implemented to process incoming messages from the network. Currently the `handle_msg(&self)` function has an implementation for the event FlooodsubMessage and one for GossipsubMessage. For instance, the function is explicitly called in the select-loop in `setup/gossipsub/gossipsub_tokio_setup.rs` or in `setup/floodsub/floodsub_mdns_behaviour.rs`.
- **network_info**: this module contains requests to a Tendermint RPC endpoint in `rpc_net_info.rs` and `rpc_status.rs` (https://docs.tendermint.com/v0.35/rpc/). `deserialize.rs` contains all structs to deserialize the JSON-RPC responses from Tendermint. `address_converter.rs` provides functions to convert the listener-address and the peer addresses from the RPC-responses into a libp2p Multiaddr format. 
- **send**: contains the function to create an internal channel to submit messages into the select-loop for broadcasting. The returned `UnboundedSender` can be used to add messages to the channel and the `UnboundedReceiver` has to be submitted to the `init`-function, such that it can be included in the select-loop.
- **setup**: contains one module for the network-setup using the Floodsub protocol and a module using the Gossipsub protocol (see below for more about these protocols). Currently, the `floodsub_tokio_setup.rs` also uses the Mdns protocol to discover automatically other peers in the *local* network. This customized network-behaviour is defined in `floodsub_mdns_behaviour.rs`. The `init` function in `floodsub_tokio_setup.rs` requires the arguments *topic* and `UnboundedReceiver`, crates a tokio-based TCP transport, builds a swarm using a random peerId, opens a random listening port and kicks off the select-loop. There are two branches in the select-loop, one for broadcasting messages to the network populated by the `UnboundedReceiver` of the channel and one branch that handles SwarmEvents. The module gossibsub currently contains one implementation with the tokio runtime and one implementation without. The `init` function in `gossipsub_tokio_setup.rs` also requires the arguments *topic* and `UnboundedReceiver` and in addition a listener and and a dial address (as Multiaddr). Then, a tokio-based TCP transport and a swarm using a random peerId are created, the given listening port is openend and the select-loop is kicked off. Again, there are two branches in the select-loop, one to broadcast messages to the network (populated by the internal channel) and another one for handling the SwarmEvents. In contrast to the floodsub implementation there is no customized network-behaviour defined for gossibsub hence, the handling of the (incoming) GossipsubEvent is directly defined inside the select-loop. The incoming messages are there passed to `handle_msg()` (from the trait `HandleMsg`) where they can be further processed.
- **lib.rs**: makes all modules accessible from outside and contains a single utility method to get the rust data type.

# How to use
The files `broadcast_floodsub.rs` and `broadcast_gossipsub.rs` mostly contain the example code of `chat-tokio.rs` and `gossipsub-chat.rs` from https://github.com/libp2p/rust-libp2p/tree/master/examples which basically implement a chat tool. Running on multiple terminals, messages typed into the cli of one peer are broadcasted to all other peers in the network. The implementations differ in the usage of the underlying protocols and the runtime: While `broadcast_floodsub.rs`/`chat-tokio.rs` use the **Floodsub** protocol to broadcast messages (and the Mdns protocols to automatically identify peers in the network) and the asynchronous **tokio** runtime (https://tokio.rs/tokio/tutorial), `broadcast_gossipsub.rs`/`gossipsub-chat.rs` use the **Gossipsub** protocol for the broadcast and **async-std**, simply an asynchronous version of the Rust standard library (https://crates.io/crates/async_std). See more about the different protocols below.<br/>
An implementation of the Gossipsub protocol together with the tokio runtime is realized in `broadcast_gossipsub_tokio.rs`.<br/>
First experiments to create a channel to forward messages internally to the event/select-loop can be found in `broadcast_floodsub.rs`.<br/>
The `broadcast_floodsub.rs` and `broadcast_gossipsub_tokio.rs` are the basis for the `floodsub_tokio_setup.rs` and `gossipsub_tokio_setup.rs` in the module setup.

There are some examples in the **bin** directory that show how to use the modules in `network/src`:
- **`test_floodsub_setup.rs`**: In this test code first, a topic for the floodsub protocol is created and a channel (a sender and a receiver) to submit messages internally to the swarm (for the select-loop). Then, the channel sender is used in a separate thread to repeatedly add a test vector to the channel. The created topic and the channel receiver are passed as arguments to the `init` function from `network::setup::floodsub::floodsub_tokio_setup`. To run this code, navigate to the `network` directory and type: `cargo run --bin test_floodsub_setup`.<br/>
Every new running instance will open a random port and will send MdnsEvents to find other peers in the local network (as defined in `setup/floodsub/floodsub_mdns_behaviour.rs`). The sent messages will be received by all other peers in the network and handled as specified in `deliver/deliver.rs`.

- **`test_tendermint_req.rs`**: This code tests the functions `get_tendermint_net_info` and `get_tendermint_status` and simply prints the response. To run this code a tendermint testnet must be running and the `test_address` used for the  request must be a RPC endpoint of one running node. When a tendermint testnet is running you can execute the code inside the `network` directory with `cargo run --bin test_tendermint_req`.

- **`test_tendermint_rpc.rs`**: This code can be used to test an RPC request using the crate `tendermint_rpc` (https://crates.io/crates/tendermint-rpc) which is a RUST implementation of the RPC core types. This can be used to deserialize JSON-RPC responses instead of defining all the types as structs by yourself (like in `network_info/deserialize.rs`). After creating an instance of `HttpClient` you can call the rpc-request directly on this client, e.g. `client.net_info()` or `client.status()`. *Warning*: The request `net_info()` is not working at the moment. You can execute this code in the `network` directory with `cargo run --bin test_tendermint_rpc`.

# About **Floodsub** and **Gossipsub**
https://docs.libp2p.io/introduction/what-is-libp2p/: Sending messages to other peers is at the heart of most peer-to-peer systems, and pubsub (short for publish / subscribe) is a very useful pattern for sending a message to groups of interested receivers.</br>
**libp2p** defines a pubsub interface for sending messages to all peers subscribed to a given “topic”. The interface currently has two stable implementations:
- **floodsub** uses a very simple but inefficient “network flooding” strategy, and
- **gossipsub** defines an extensible gossip protocol.

More sources:
- https://docs.libp2p.io/concepts/publish-subscribe/
- https://github.com/libp2p/specs/tree/master/pubsub
- https://github.com/libp2p/specs/tree/master/pubsub/gossipsub#implementation-status

# About **tokio** and **async_std**

Both are asynchronous runtimes for Rust that don't seem to differ much from each other. Since **tokio** has a larger ecosystem than **async_std** it might be reasonable to go with this runtime.

tokio:
- https://tokio.rs/
- https://tokio.rs/tokio/tutorial

async_std:
- https://crates.io/crates/async_std
- https://book.async.rs/