# Threshold Crypto Library API (RUST Version)

This library uses [Miracl Core](https://github.com/miracl/core) for the discrete logarithm schemes and [gmp-mpfr-sys](https://crates.io/crates/gmp-mpfr-sys) as a [GMP](https://gmplib.org/) wrapper for the RSA schemes.<br><br>

**ThresholdCoin**<br>
- **`create_share(name: &[u8], sk: &PrivateKey, rng: &mut RNG) -> Result<CoinShare, ThresholdCryptoError>`**
- **`verify_share(share: &CoinShare, name: &[u8], pk: &PublicKey) -> Result<bool, ThresholdCryptoError>`**
- **`assemble(shares: &Vec<CoinShare>) -> Result<u8, ThresholdCryptoError>`**
<br><br>

**ThresholdCipher**<br>
- **`encrypt(msg: &[u8], label: &[u8], pk: &PublicKey) -> Result<Ciphertext, ThresholdCryptoError>`**
- **`verify_ciphertext(ct: &Ciphertext, pk: &PublicKey) -> Result<bool, ThresholdCryptoError>`**
- **`partial_decrypt(ct: &Ciphertext, sk: &PrivateKey) -> Result<DecryptionShare, ThresholdCryptoError>`**
- **`verify_share(sh: &DecryptionShare, ct: &Ciphertext, pk: &PublicKey) -> Result<bool, ThresholdCryptoError>`**
- **`assemble(ct: &Ciphertext, shares: &Vec<DecryptionShare>]) -> Result<Vec<u8>, ThresholdCryptoError>`**
<br><br>

**ThresholdSignature**<br>
- **`verify(sig: &SignedMessage, &pk: &PublicKey) -> Result<bool, ThresholdCryptoError>`**
- **`partial_sign(msg: &[u8], sk: &PrivateKey) -> Result<SignatureShare, ThresholdCryptoError>`**
- **`verify_share(share: &SignatureShare, msg: &[u8], pk: &PublicKey) -> Result<bool, ThresholdCryptoError>`**
- **`assemble(shares: &Vec<SignatureShare>, msg: &Vec<u8>) -> Result<bool, ThresholdCryptoError>`**
<br><br>

To use one of the threshold schemes, we first have to create the public/private keys using the `KeyGenerator`.

**KeyGenerator**<br>
- **`generate_keys(sig: &SignedMessage, &pk: &PublicKey) -> Result<bool, ThresholdCryptoError>`**


**Share** <br>
- **`get_id(&self) -> usize`**
<br><br>

**Ciphertext**<br>
- **`get_label(&self) -> Vec<u8>`**
- **`get_message(&self) -> Vec<u8>`**
<br><br>

**PublicKey** <br>
<br>

**PrivateKey** <br>
- **`get_id(&self) -> usize`**
- **`get_public_key(&self) -> PublicKey`**
<br><br>

## **Miracl Core Integration**

The underlying cryptography library [Miracl Core](https://github.com/miracl/core) implements various elliptic curves and different versions of big integer arithmetic. To use those primitives interchangeably in our threshold schemes, we need a wrapper around the library methods. This is mainly done using the enums `BigImpl` and `GroupElement`. <br>
Miracl implements new structs `BIG` and `ECP` for each curve containing the corresponding big integer arithmetic and elliptic curve point implementations respectively. The first layer of abstraction for big integers is the trait `BigInt`:
<br><br>

**BigInt** <br>
- **`new() -> BigImpl`**
- **`new_big(y: &BigImpl) -> BigImpl`**
- **`new_ints(a: &[Chunk]) -> BigImpl`**
- **`new_int(i: isize) -> BigImpl`**
- **`new_copy(y: &BigImpl) -> BigImpl`**
- **`new_rand(q: &BigImpl, rng: &mut RNG) -> BigImpl`**
- **`from_bytes(bytes: &[u8]) -> BigImpl`**
- **`rmod(&mut self, y: &BigImpl)`**
- **`mul_mod(&mut self, y: &BigImpl, m: &BigImpl)`**
- **`inv_mod(&mut self, m: &BigImpl)`**
- **`add(&mut self, y: &BigImpl)`**
- **`sub(&mut self, y: &BigImpl)`**
- **`imul(&mut self, i: isize)`**
- **`pow_mod(&mut self, y: &BigImpl, m: &BigImpl)`**
- **`to_bytes(&self) -> Vec<u8>`**
- **`to_string(&self) -> String`**
- **`equals(&self, y: &BigImpl) -> bool`**
<br><br>

The second layer is the enum `BigImpl`, indicating which implementation a particular object belongs to (such that objects from different groups with the same underlying implementation can interact with each other):

    pub enum BigImpl {
        Bls12381(Bls12381BIG),
        Bn254(Bn254BIG),
        Ed25519(Ed25519BIG),
        ...
    }

`BigImpl` also implements the methods of the `BigInt` trait and the schemes therefore rely on `BigImpl`. Next we need to create an abstraction for the different elliptic curve point implementations:

The first layer of abstraction is the union `GroupData` containing one field for each curve. As it is a union, the different fields share the memory location and therefore do not take up more space than is needed.

    #[repr(C)]
    pub union GroupData {
        pub bls12381: ManuallyDrop<Bls12381>,
        pub bn254: ManuallyDrop<Bn254>,
        pub ed25519: ManuallyDrop<Ed25519>,
        ...
    }

The next layer is the struct `GroupElement` with two members: Once a `data` field containing a `GroupData` object and an enum of type `Group` defining the curve the `data`object belongs to.

    pub struct GroupElement {
        group: Group,
        data: GroupData
    }

    pub enum Group {
        Bls12381 = 0,
        Bn254 = 1,
        Ed25519 = 2,
        Rsa512 = 3,
        Rsa1024 = 4,
        Rsa2048 = 5,
        Rsa4096 = 6
    }

The `GroupElement` struct implements various group operations and can therefore be used in the implementation of the schemes as a curve agnostic data type. Not all groups implement all operations though. Some of the curves support pairing operations, others don't. You can determine whether a group supports pairings by calling `supports_pairings()` on a `Group` object.
