# Protocols

Threshold protocols are implemented in the `src/` directory, e.g.,
`src/threshold_cipher`.

By now we support `threshold_chipher`, `threshold_signature`, `threshold_coin` implementations.

For every type of protocol implemented, there should be a dedicated directory that internally provides the following structure:

```
- src
| - threshold_cipher
| | - protocols.rs
| | - message_types.rs
| | - mod.rs
```

Sections below detail what every file should contain.

## Functions in a protocol

A protocol must expose two functions, run() and terminate().
The caller should only have to call run() to start the protocol instance.

- About run():
The function run() runs for the whole lifetime of the instance and implements the protocol logic.
In the beginning, it must make the necessary validity checks (e.g., the validity of ciphertext).
There is a loop(), which handles incoming shares. The loop exits when the instance is finished.
This function is also responsible for returning the result to the caller.

- About terminate():
It is called by the instance to clean up any remaining data.

### Fields in a protocol

Protocol types contain the following fields.
See for example the `ThresholdCipherProtocol` in `src\threshold_cipher/protocol.rs`.

- chan_in:
The receiver end of a channel. Messages (e.g., decryption shares) destined for this instance will be received here.
- chan_out:
The sender end of a channel. Messages (e.g., decryption shares) to other nodes are to be sent trough this channel.
- key:
Of type `Arc<protocols::types::Key>`, defined in `../orchestration/src/types.rs`.
The secret key and public keys, of type `schemes::keys::PrivateKey` and `schemes::keys::PublicKey` respectively, as accessible as `key.sk` and `key.sk.get_public_key`.
The threshold is also accessible as `key.sk.get_threshold()`.

## Protocol messages

Each protocol implementation is responsible for defining its message types in `src\<protocol_name>\message_types.rs`,
and for implementing two functions for each message type,
`try_from_bytes()`and `to_net_message()`.
For example, the `ThresholdCipherProtocol` uses a single message type, called `DecryptionShareMessage`,
defined in `src\threshold_cipher\message_types.rs`.

The interface between the network and a protocol is the following.
A protocol instance receives on `chan_in` incoming messages as `Vec<u8>` and sends on `chan_out` outgoing
messages of type `NetMessage` (this type is defined in the `network` crate, see the corresponding README).

- `try_from_bytes()`: Takes a `Vec<u8>` and returns an instance of the message type, if the
bytes can be deserialized to that message type.
It is called by the protocol whenever a message is received. The idea is that the protocol calls
`try_from_bytes()` on each message type. The protocol can then handle each message according to its specifications.
Importantly, as the protocol knows the type of the incoming message, it knows whether it was delivered in total order or not.
- `to_net_message()`: It returns a `NetMessage` and is called when a protocol wants to send a message.
This function must set the `is_total_order` field of `NetMessage` to `true` if the protocol requires
the corresponding message to be sent through the total-order channel.
