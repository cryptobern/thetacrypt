# Orchestration package

Once an instance it's been create as a response to an RPC request a new thread handles a single protocol execution. To be able to manage the interaction with the network and maintain the state about the progress of said instance, some orchestration modules are needed. 

In particular, there exist on separate tokio threads, the `StateManager` for keeping state and a `MessageDispatcher` for dispatching incoming messages to the appropriate instance.

## State and state manager

We use the "share memory by communicating" paradigm.
The `StateManager`, defined in `src\state_manager.rs`, is responsible for keeping _any_ type of state related to request handler and requests (status of a request, such as started or terminated, results of terminated requests, etc).
It is spawned as a separate Tokio task in the `init()` function of `src\rpc_request_handler.rs`.
The `StateManager` only keeps the state, and does not implement any other logic (e.g., when to start a request, when to update the status of a request).

Any state query or update _must_ happen through the `StateManager`. To this end, the `StateManager` listens for
`StateUpdateCommand`s on the receiver end of a channel, named `state_command_receiver`. Any other thread, owing a clone
of `state_command_sender` can submit state queries/updates. All these queries/updates are serialized in the 
`state_command_sender -> state_command_receiver` channel and processed serially by the `StateManager`

When the `StateManager` must return a value as response to `StateUpdateCommand` (e.g., `StateUpdateCommand::GetInstanceStatus`),
then this value is also returned via a channel. The caller creates a `oneshot::channel` and
sends the sender end (`tokio::sync::oneshot::Sender`) as part of the `StateUpdateCommand`.
The `StateManager` will use this sender to respond, and the receiver awaits it on the corresponding receiver end.

## MessageDispatcher

The `MessageDispatcher`, defined in `src\message_dispatcher.rs`, is responsible for dispatching received messages (received from the p2p network) to the appropriate protocol instance (e.g., decryption shares to the corresponding threshold-decryption protocol instance).
It is spawned as a separate Tokio task in the `init()` function of `src\rpc_request_handler.rs`.
The `MessageDispatcher` maintains a channel with _every_ protocol instance, where the sender end is owned 
by `MessageDispatcher` (see `instance_senders` variable)
and the receiver end by the protocol. An instance is identified by its instance_id.
The `MessageDispatcher` constantly listens on `incoming_message_receiver` (the network layer owns the sender end
of this channel) and forwards received messages to the appropriate instance, using the appropriate `instance_sender`.

*Note:* The channels for communication between the `MessageDispatcher` and protocol instances is an exception to the rule
that all state is handled by the `StateManager`.
This is because only the `MessageDispatcher` needs to know how to reach each instance, i.e.,
the `MessageDispatcher` is the only responsible for maintaining these channels.
When a new protocol instance is started, and when a protocol instance terminates, the `RpcRequestHandler` must inform the `MessageDispatcher`. This is done using a `MessageDispatcherCommand`.
Specifically, when a new protocol instance is created, the `RpcRequestHandler` informs the `MessageDispatcher` by sending a `MessageDispatcherCommand::InsertInstance`. This includes the id of the new instance and a response channel.
The `MessageDispatcher` creates a channel (which will be used to reach the new instance), keeps the sender end of this
channel and sends the receiver end back to the `RpcRequestHandler` (who in turn passes it to the newly created instance).
When a protocol instance is created, the `RpcRequestHandler` informs the `MessageDispatcher` by sending a `MessageDispatcherCommand::RemoveInstance`.

### Backlog

A logic for backlogging messages is implemented in the `MessageDispatcher`.
This is necessary for the case when (due to asynchrony) a message (such as a decryption share) for an instance is received before
the instance is started (because the actual request was delayed).

## Key management

Notice that by *key* we always refer to a **private key (share)**. The `KeyStore` always returns private keys. The corresponding public key is accessible through the private.

Keys are represented by `struct Key` in `types.rs`.
It contains the public fields `id`, which uniquely represents a key entry, and `sk`, which contains the actual secret key
of type `schemes::keys::PrivateKey` (through which we have access to the corresponding public key as `sk.get_public_key()`), and some private metadata used internally by `KeyStore`.

The logic for handling keys is encapsulated in `struct KeyStore` in `keystore.rs`.
It exposes methods for creating, (de)serializing, and retrieving keys, such as `get_key_by_id()` and `get_key_by_scheme_and_group()`.
There is a certain logic regarding which keys are returned each time and which are considered default.
This is documented in comments in `keystore.rs`.

### Reading from a file upon server initialization

Right now keys are read from file "keys_<replica_id>" upon initialization in `server.rs`.
It is possible to create keys for every possible combination of algorithm and domain through the binary `ThetaCLI` under `bin` in the root workspace directory.

## Tests

Tests are written in `\test` directory, using either the `#[test]` attribute for unit tests or the `tokio::test` for integration tests.
Always run the tests when making changes to the code. You can do that using `cargo test`.

**Remark**: The tests in `test-rpc-client-*.rs` files require 4 server instances to be running, otherwise they will fail.
Start these server instances exactly as described in the main guide in the root directory.