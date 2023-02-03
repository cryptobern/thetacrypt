The `protocols` package implements threshold-cryptographic protocols and an RPC server that instantiates them.

# Exposing protocols over RPC
All implemented protocols can be started by sending the corresponding RPC request to the provided RPC server.

The RPC types are defined in `protocol_types.proto` of the `proto` crate. Currently, the following endpoints are implemented:
- decrypt()
- get_decrypt_result()
- decrypt_sync()
- get_public_keys_for_encryption()

See the documentation for each of them in `protocol_types.proto`.

# How to use the RPC server and client
The server is implemented in `src\rpc_request_handler.rs` and can be started using `src\bin\server.rs`.
From the root directory of the `protocols` project start 4 terminals and, for i = 1...4, run:
```
cargo run --bin server <i> -l
```
You should see each server process print that it is connected to the others and ready to receive client requests.

An example RPC client can be found in `\src\bin\client.rs`. To run this client, open a new terminal and run:
```
cargo run --bin client
```
This client binary uses the `decrypt()` and `decrypt_sync()` RPC endpoints.


# The RPC request handler
The RPC request handler (defined in the `protocol_types.proto` of the `proto` crate) is implemented in `src\rpc_request_handler.rs` by the `RpcRequestHandler` struct. The logic is the following:
- The request handler is constantly listening for requests. The corresponding handler method (e.g., `decrypt()`, `decrypt_sync()`, `get_decrypt_result()`, etc.) is run every time a request is received.
- For every received request (e.g., `DecryptRequest` for the `decrypt()` endpoint) make all the required correctness checks and then start a new protocol (in our example a `ThresholdCipherProtocol`) instance in a new tokio thread.
- Each instance is assigned and identified by a unique `instance_id`. For example, a threshold-decryption instance is identified by the concatenation of the `label` field (which is part of `DecryptRequest.ciphertext`) and the hash of the ciphertext.
- There exist separate tokio threads for handling the state and for forwarding incoming messages to the appropriate instance, as described in the following.

### State and state manager
We use the "share memory by communicating" paradigm.
There exists a Tokio task, the `StateManager`, spawned in the `init()` function of `src\rpc_request_handler.rs`, that is responsible for keeping _any_ type of state related to request handler and requests (status of a request, such as started or terminated, results of terminated requests, etc).
It only keeps the state, and does not implement any other logic (e.g., when to start a request, when to update the status of a request).

Any state query or update _must_ happen through the `StateManager`. To this end, the `StateManager` listens for
`StateUpdateCommand`s on the receiver end of a channel, named `state_command_receiver`. Any other thread, owing a clone
of `state_command_sender` can submit state queries/updates. All these queries/updates are serialized in the 
`state_command_sender -> state_command_receiver` channel and processed serially by the `StateManager`

When the `StateManager` must return a value as response to `StateUpdateCommand` (e.g., `StateUpdateCommand::GetInstanceStatus`),
then this value is also returned via a channel. The caller creates a `oneshot::channel` and
sends the sender end (`tokio::sync::oneshot::Sender`) as part of the `StateUpdateCommand`.
The `StateManager` will use this sender to respond, and the receiver awaits it on the corresponding receiver end.

### MessageForwarder
The `MessageForwarder` is responsible for forwarding received messages (received from the network) to the appropriate
protocol instance (e.g., decryption shares to the corresponding threshold-decryption protocol instance).
The `MessageForwarder` maintains a channel with _every_ protocol instance, where the sender end is owned 
by `MessageForwarder` (see `instance_senders` variable)
and the receiver end by the protocol. An instance is identified by its instance_id.
The `MessageForwarder` constantly listens on `incoming_message_receiver` (the network layer owns the sender end
of this channel) and forwards received messages to the appropriate instance, using the appropriate `instance_sender`.

*Note:* The channels for communication between the `MessageForwarder` and protocol instances is an exception to the rule
that all state is handled by the `StateManager`.
This is because only the `MessageForwarder` needs to know how to reach each instance, i.e.,
the `MessageForwarder` is the only responsible for maintaining these channels.
When a new protocol instance is started, and when a protocol instance terminates, the `RpcRequestHandler` must inform the `MessageForwarder` about the
existence of the new instance. This is done using a `MessageForwarderCommand`.

### Backlog
A logic for backlogging messages is implemented in the `MessageForwarder`. 
This is necessary for the case when (due to asynchrony) a message (such as a decryption share) for an instance is received before
the instance is started (because the actual request was delayed).

### Assigning instance-id
Each protocol instance must be assigned an 'instance_id'.
This identifies the instance and will be used to forward messages (e.g., decryption shares for a threshold-decryption instance) to the corresponding instance.
The logic for assigning instance ids is abstracted in functions such as `assign_decryption_instance_id()`.



# Protocols
Threshold protocols are implemented in the `src\` directory, e.g.,
`src\threshold_cipher_protocol.rs`.

### Functions in a protocol
A protocol exposes two functions, run() and terminate().
The caller should only have to call run() to start the protocol instance.

- About run():
The idea is that it runs for the whole lifetime of the instance and implements the protocol logic.
In the beginning it must make the necessary validity checks (e.g., validity of ciphertext).
There is a loop(), which handles incoming shares. The loop exits when the instance is finished.
This function is also responsible for returning the result to the caller.

- About terminate():
It is called by the instance to clean up any data.

### Fields in a protocol
Protocol types contain the following fields.
See for example the `ThresholdCipherProtocol` in `src\threshold_cipher_protocol.rs`. 
- chan_in:
The receiver end of a channel. Messages (e.g., decryption shares) destined for this instance will be received here.
- chan_out:
The sender end of a channel. Messages (e.g., decryption shares) to other nodes are to be sent trough this channel.
- key:
Of type `Arc<protocols::types::Key>`, defined in `protocol/types.rs`. 
The secret key and public keys, of type `schemes::keys::PrivateKey` and `schemes::keys::PublicKey`, respectively, as accessible as
`key.sk` and `key.sk.get_public_key`.
The threshold is also accessible as `key.sk.get_threshold()`.



# Key management
Notice that by *key* we always refer to a private key. The `KeyChain` always returns private keys. The corresponding public key is accessible through the private.

Keys are represented by `struct Key` in `common_types.rs`.
It contains the public fields `id`, which uniquely represents a key entry, and `sk`, which contains the actual secret key
of type `schemes::keys::PrivateKey` (through which we have access to the corresponding public key as `sk.get_public_key()`),
and some private metadata used internally by `KeyChain`.

The logic for handling keys is encapsulated in `struct KeyChain` in `keychain.rs`.
If exposes methods for creating, (de)serializing, and retrieving keys, such as ` get_key_by_id()` and `get_key_by_scheme_and_group()`.
There is a certain logic regarding which keys are returned each time and which are considered default.
This is documented in comments in `keychain.rs`.

### Reading from a file upon server initialization
Right now keys are read from file "keys_<replica_id>" upon initialization in `server.rs`.
There is one key for every possible combination of algorithm and domain. In the future, the user should
be able to ask our library to create more keys.


### Tests
Tests are written in `\test` directory, using either the `#[test]` attribute for unit tests or the `tokio::test` for integration tests.

Run the tests with `cargo test`.