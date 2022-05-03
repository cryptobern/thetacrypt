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

### State
The state of the request handler currently is owned by the `ThresholdProtocolService`.
It is initialized in the `tokio::main` function and then moved into `ThresholdProtocolService`.
The methods that implement the service (such as `async fn decrypt`) only have an *immutable* reference to it, so it is essentially a read-only state.