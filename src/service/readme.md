# The service layer

The `service` package implements threshold-cryptographic protocols and an RPC server that instantiates them.
All implemented protocols can be started by sending the corresponding RPC request to the provided RPC server.

## Exposing protocols over RPC

The RPC types are defined in `protocol_types.proto` of the `proto` crate. Currently, the following methods are implemented:

- get_public_keys_for_encryption()
- decrypt()
- get_decrypt_result()
- sign()
- get_signature_result()
- flip_coin()
- get_coin_result()

See the documentation for each of them in `../proto/protocol_types.proto`.

## The RPC request handler

The RPC request handler (defined in the `protocol_types.proto` of the `proto` crate) is implemented in `src\rpc_request_handler.rs` by the `RpcRequestHandler` struct. The logic is the following:

- The request handler is constantly listening for requests. The corresponding handler method (e.g., `decrypt()`, `get_decrypt_result()`, etc.) is run every time a request is received.
- For every received request (e.g., `DecryptRequest` for the `decrypt()` endpoint) make all the required correctness checks and then start a new protocol (for example a `ThresholdCipherProtocol`) instance in a new tokio thread.
- Each instance is assigned and identified by a unique `instance_id`. For example, a threshold-decryption instance is identified by the concatenation of the `label` field (which is part of `DecryptRequest.ciphertext`) and the hash of the ciphertext.

### Assigning instance-id

Each protocol instance must be assigned an 'instance_id'.
This identifies the instance and will be used to forward messages (e.g., decryption shares for a threshold-decryption instance) to the corresponding instance.
The logic for assigning instance ids is abstracted in functions such as `assign_decryption_instance_id()`.
