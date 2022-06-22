A `Protocol` (`ThresholdCipherProtocol` or `ThresholdSignatureProtocol`) has the following interface:
- on_init()
- inChan: Used for incoming messages (such as threshold decryption shares)
- outChan: Used for outgoing messages

The request handling code is implemented in the `ThresholdProtocolService`. It has the following endpoints:
- decrypt: Start a `ThresholdCipherProtocol`.
- sign; Start a `ThresholdSignatureProtocol`.
- store_decryption_share: Used to send a decryption share to an existing threshold cipher protocol.
- store_signature_share: Used to send a signature share to an existing threshold cipher protocol.

Currently a `Request`, (`ThresholdDecryptionRequest` or `ThresholdSignatureRequest`) does not contain
a unique identifier. Hence, the application is responsible to make sure it sends each request once to the
threshold crypto library.

The request handling code in the library uniquely identifies a `ThresholdDecryptionRequest` by the `label`
field, which is serialized inside `ThresholdDecryptionRequest.ciphertext`, and a `ThresholdSignatureRequest`
by the field `ThresholdSignatureRequest.message`.


### Request Handler:
The idea is that there exists a single request handler struct (the ThresholdProtocolService),
and the corresponding handler method is run every time a request is received.
It checks the exact type of the request and starts the appropriate protocol as a new tokio task.
Each protocol (tokio task) owns: 
1) chan_in: the receiver end of a network-to-protocol channel, used for receiving messages (such as shares) from the network, and
2) chan_out: the sender end of a protocol-to-network channel, used for sending messages to the network.
These channels are created by the handler just before spawning the new tokio task.

### State
The state of the request handler currently is owned by the `ThresholdProtocolService`.
It is initialized in the `tokio::main` function and then moved into `ThresholdProtocolService`.
The methods that implement the s

### State Manager:
Responsible for keeping all the state related to requests (open/terminated).
It only keeps the state, and does not implement any other logic (e.g., when to store
a result of a request).
There exists a separate Tokio task, the `StateManager`, responsible for the following:
1) Handling the state of the request handler, i.e., the sender ends of the `network-to-protocol` channels
and the receiver ends of `protocol-to-network` channels.
The `StateManager` is created once, in the `tokio::main` function. It exposes a sender channel end to the request handler,
called `state_manager_sender`. All updates to the state (i.e., adding and removing network-to-protocol and protocol-to-network
channels, querying the state) take place by sending a `StateUpdateCommand` on `state_manager_sender`.
2) It loops over all protocol-to-network channels and forwards the messages to the Network.
3) It loops over all result-channels and handles the result of each instance.
4) When the `RequestHandler` receives a decryption share (`push_decryption_share` method) it uses the `StateManager`
to retrieve the appropriate network-to-protocol channel and then sends the share over that channel.


When the `StateManager` must return a value as response to `StateUpdateCommand` (e.g., `GetNetToProtSender`, `GetInstanceIdExists`),
then this value is also returned via a channel. The caller (e.g., the `RequestHandler`) creates a `oneshot::channel` and
sends the sender end (`tokio::sync::oneshot::Sender`) with the command. The `StateManager` will send the response through
this sender, and the receiver gets it back on the corresponding receiver end.

*todo*: The `StateManager` runs a busy loop. Can we change this?
The State Manager is spawned in a dedicated OS thread, not on a Tokio "green" thread, for the following reason:
Currently, the best way I have found to make the State manager loop over the state_manager_receiver and all the
prot_to_net channels is by having a `loop()` and `try_receive()` inside (maybe this is possible with `tokio::select!`,
but don't know how). But this means the State Manager will be running a busy loop forever (there is no `.await`).
If we run this as a Tokio task, it will be constantly running, causing other Tokio tasks to starve.
        
*todo*: Set tokio::runtime to use default - 1 worker threads, since we are using 1 for the state manager.
https://docs.rs/tokio/1.2.0/tokio/attr.main.html
https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html#examples-2

### Key management:
Right now keys are read from file "keys_<replica_id>" upon initialization (in the tokio::main function).
There is one key for every possible combination of algorithm and domain. In the future, the user should
be able to ask our library to create more keys.
Each key is uniquely identified by a key-id and contains the secret key (through which we have access
to the corresponding public key and the threshold) and the key metadata (for now, the algorithm and domain
it can be used for).
When a request is received, we use the key that corresponds to the algorithm and DlGroup fields of the request.
todo: Redesign this. The user should not have to specify all of the algorithm, domain, and key. Probably only key?

### Context:
Context variable that contains all the variables required by the Request Handler and the protocols.
There must exist only one instance of Context.

### Assigning instance-id
Each incoming request (e.g., 'ThresholdDecryptionRequest' on 'ThresholdSignatureRequest' request) must be assigned an 'instance_id'.
This identifies each protocol instance with a unique id. This id will be used to forward decryption shares to the corresponding protocol instance.
It is also returned to the caller (e.g., through the 'ThresholdDecryptionResponse' or 'ThresholdSignatureResponse').
The logic for assigning an id to each protocol instance is abstracted in the functions `assign_decryption_instance_id()`, `assign_signature_instance_id()`.

TODOs:
- There are many clone() calls, see if you can avoid them (especially in the request handler methods that are executed often, eg cloning keys).
- There are many unwrap(). Handle failures.
