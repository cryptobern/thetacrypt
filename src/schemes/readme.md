# Schemes layer 

There are 3 kinds of threshold schemes available: `ThresholdCipher`, `ThresholdSignature` and `ThresholdCoin`. For each of the three categories, the following schemes are implemented:

Threshold Ciphers:
- Sg02 (ZK-based)
- Bz03 (Pairing-based)

Threshold Signatures:
- Bls04 (Pairing-based)
- FROST (ZK-based)
- Sh00 (Threshold RSA)

Threshold Coins:
- Cks05 (ZK-based)

All of those schemes use keys of the type `PublicKey` or `PrivateKey` respectively. Keys can be generated using the `KeyGenerator`. To generate keys, the concrete scheme and the underlying group need to be specified. For the schemes that are pairing-based, a group that supports pairings needs to be specified. So far the following groups are implemented:

- Bls12381 (supports pairings)
- Bn254 (supports pairings)
- Ed25519 (no pairings)
<br>

## Demo
You can find an example program in the folder `src/examples/main.rs` that shows how to use the schemes layer.

## Key Generation
To generate a vector of private keys, use

    let private_keys = KeyGenerator::generate_keys(
        K, 
        N, 
        &mut RNG::new(RngAlgorithm::MarsagliaZaman), 
        &ThresholdScheme::Sg02, 
        &Group::Bls12381)
        .unwrap();

where 
- `K` = threshold
- `N` = total private keys
- `RNG` = random number generator to be used, here a MarsagliaZaman algorithm is used
- `ThresholdScheme` = the scheme that should be used
- `Group` = the underlying group

Once the keys are generated, the API for all schemes/groups stays the same. One can put the keys into use using the structs below:

## Threshold Cipher
In threshold encryption one participant encrypts a message using the public key. To retrieve the original plaintext from a ciphertext, `K` out of `N` participants holding a private key need to create a decryption share (using `partial_decrypt`) which then are combined resulting in a decrypted ciphertext. Decryption shares as well as the ciphertext should be verified before assembling the shares resp. before creating a decryption share to prevent CCA attacks.

The interface of `ThresholdCipher` is as follows:

**ThresholdCipher**<br>
- **`encrypt(msg: &[u8], label: &[u8], pubkey: &PublicKey, params: &mut ThresholdCipherParams) -> Result<Ciphertext, ThresholdCryptoError>`**
- **`verify_ciphertext(ct: &Ciphertext, pubkey: &PublicKey) -> Result<bool, ThresholdCryptoError>`**
- **`verify_share(share: &DecryptionShare, ct: &Ciphertext, pubkey: &PublicKey) -> Result<bool, ThresholdCryptoError>`**
- **`partial_decrypt(ct: &Ciphertext, privkey: &PrivateKey, params: &mut ThresholdCipherParams) -> Result<DecryptionShare, ThresholdCryptoError>`**
- **`assemble(shares: &Vec<DecryptionShare>, ct: &Ciphertext) -> Result<Vec<u8>, ThresholdCryptoError>`** 

**ThresholdCipherParams**<br>
- **`new() -> Self`**
- **`set_rng(&mut self, alg: RngAlgorithm) -> Self`**

## Threshold Signature
`K` out of `N` participants partially sign a message and those partial signatures are then assembled to a single full signature which can be verified alone without knowing the partial signatures. The signature shares should be verified before assembling to prevent attacks.

The interface of `ThresholdSignature` is as follows:

**ThresholdSignature**<br>
- **`partial_sign(msg: &[u8], label: &[u8], secret: &PrivateKey, params: &mut ThresholdSignatureParams) -> Result<SignatureShare, ThresholdCryptoError> `**
- **`verify_share(share: &SignatureShare, msg: &[u8], pubkey: &PublicKey) -> Result<bool, ThresholdCryptoError> `**
- **`assemble(shares: &Vec<SignatureShare>, msg: &[u8], pubkey: &PublicKey) -> Result<Signature, ThresholdCryptoError> `**
- **`verify(sig: &Signature, pubkey: &PublicKey, msg: &[u8]) -> Result<bool, ThresholdCryptoError>`** 

**ThresholdSignatureParams**<br>
- **`new() -> Self`**
- **`set_rng(&mut self, alg: RngAlgorithm) -> Self`**

Additionally the library supports threshold signature schemes that need interaction between the different parties. For such schemes, an `InteractiveThresholdSignature` instance is needed:

**InteractiveThresholdSignature**<br>
- **`new(key: &PrivateKey, msg: &[u8], label: &[u8]) -> Result<Self, ThresholdCryptoError>`** 
- **`do_round(&mut self) -> Result<RoundResult, ThresholdCryptoError> `**
- **`update(&mut self, round_result: &RoundResult) -> Result<(), ThresholdCryptoError> `**
- **`has_next_round(&self) -> bool `**
- **`is_ready_for_next_round(&self) -> bool `**
- **`get_signature(&self) -> Result<Signature, ThresholdCryptoError>`** 
- **`get_label(&self) -> Vec<u8>`**

## Threshold Coin
Threshold Coin schemes are used to collaboratively generate randomness (one random bit). Each random coin has a name that all participants need to know. `K` out of `N` participants create coin shares using the name of the coin and those shares can then be verified and assembled to retrieve the random coin.

The interface of `ThresholdCoin` is as follows:

**ThresholdCoin**<br>
- **`create_share(name: &[u8], private_key: &PrivateKey, rng: &mut RNG) -> Result<CoinShare, ThresholdCryptoError> `**
- **`verify_share(share: &CoinShare, name: &[u8],  public_key: &PublicKey) -> Result<bool, ThresholdCryptoError> `**
- **`assemble(shares: &Vec<CoinShare>) -> Result<u8, ThresholdCryptoError> `**

## Serialization
The keys, decryption/signature/coin shares and signatures all implement the `Serializable` trait which implements methods for converting to/from a byte stream: 

    pub trait Serializable:
        Sized
        + Clone
        + PartialEq {
        fn serialize(&self) -> Result<Vec<u8>, ThresholdCryptoError>;
        fn deserialize(bytes: &Vec<u8>) -> Result<Self, ThresholdCryptoError>;
    }

## Error handling
If something fails in one of the methods described above, a `ThresholdCryptoError` is returned, indicating what went wrong:

    pub enum ThresholdCryptoError {
        WrongGroup,
        WrongScheme,
        WrongKeyProvided,
        SerializationFailed,
        DeserializationFailed,
        CurveDoesNotSupportPairings,
        ParamsNotSet,
        IdNotFound,
        IncompatibleGroup,
        WrongState,
        PreviousRoundNotExecuted,
        InvalidRound,
        InvalidShare,
        ProtocolNotFinished,
        NotReadyForNextRound,
        MessageNotSpecified,
        MessageAlreadySpecified,
        SerializationError(String),
        UnknownScheme,
    }