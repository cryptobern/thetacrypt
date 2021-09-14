# Threshold Crypto Library API (RUST Version)

In Rust, no such concept as inheritance exists. Instead, the language uses the concept of "composition over inheritance," which means we have to structure the API differently. In this document, RUST notation and datatypes will be used. The library is built upon [Miracl Core](https://github.com/miracl/core).<br><br>

## **Scheme Traits**
The following three traits define the main interface of the different schemes. Additionally, each implementation of those traits should have a method `generate_keys`, that isn't included in the traits as the parameters may change depending on the underlying implementation.

**ThresholdCoin**<br>
- **`type PK: PublicKey`**
- **`type SK: PrivateKey`**
- **`type SH: Share`**<br><br>
- **`create_share(name: &[u8], sk: &Self::SK, rng: &mut impl RAND) -> Self::SH`**
- **`verify_share(share: &Self::SH, name: &[u8], pk: &Self::PK) -> bool`**
- **`assemble(shares: &Vec<Self::SH>) -> u8`**
<br><br>

**ThresholdCipher**<br>
- **`type CT: Ciphertext`**
- **`type PK: PublicKey`**
- **`type SK: PrivateKey`**
- **`type SH: Share`**  <br><br>
- **`encrypt(msg: &[u8], label: &[u8], pk: &Self::PK) -> Self::CT`**
- **`verify_ciphertext(ct: &Self::CT, pk: &Self::PK) -> bool`**
- **`partial_decrypt(ct: &Self::CT, sk: &Self::SK) -> Self::SH`**
- **`verify_share(sh: &Self::SH, ct: &Self::CT, pk: &Self::PK) -> bool`**
- **`assemble(ct: &Self::CT, shares: &Vec<Self::SH>]) -> Vec<u8>`**
<br><br>

**ThresholdSignature**<br>
- **`type SM`**
- **`type PK: PublicKey`**
- **`type SK: PrivateKey`**
- **`type SH: Share`**<br><br>
- **`verify(sig: &Self::SM, &pk: &Self::PK) -> bool`**
- **`partial_sign(msg: &[u8], sk: &Self::SK) -> Self::SH`**
- **`verify_share(share: &Self::SH, msg: &[u8], pk: &Self::PK) -> bool`**
- **`assemble(shares: &Vec<Self::SH>, msg: &Vec<u8>) -> bool`**
<br><br>

The above traits define the types that are used in the corresponding scheme such as the public/private keys and shares. Those types rely on the following traits:

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
- **`type PK: PublicKey`**
- **`get_id(&self) -> usize`**
- **`get_public_key(&self) -> Self::PK`**
<br><br>

## **Miracl Core Integration**

The underlying cryptography library [Miracl Core](https://github.com/miracl/core) implements various elliptic curves and different versions of big integer arithmetic. To use those primitives interchangeably in our threshold schemes, we need a wrapper around the library methods. This is mainly done using the traits `BigInt`, `DlGroup` and `PairingEngine`. <br>
Miracl implements new structs `BIG` and `ECP` for each curve containing the corresponding big integer arithmetic and elliptic curve point implementations respectively. The first layer of abstraction for big integers is the trait `BigInt`:
<br><br>

**BigInt** <br>
- **`new() -> BigImpl`**
- **`new_big(y: &BigImpl) -> BigImpl`**
- **`new_ints(a: &[Chunk]) -> BigImpl`**
- **`new_int(i: isize) -> BigImpl`**
- **`new_copy(y: &BigImpl) -> BigImpl`**
- **`new_rand(q: &BigImpl, rng: &mut impl RAND) -> BigImpl`**
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

`BigImpl` also implements the methods of the `BigInt` trait and the schemes therefore rely on `BigImpl`. Next trait is the `DlGroup` trait which wraps the different elliptic curve point implementations:

**DlGroup** <br>
- **`type BigInt: BigInt`**
- **`type DataType`** <br><br>
- **`get_order(&self) -> BIG`**
- **`new() -> Self`** returns generator                            
- **`new_big(x: &BigImpl) -> Self`** returns generator^x
- **`new_rand(rng: &mut impl RAND) -> Self`** returns random element in group
- **`mul(&mut self, g: &Self)`**            
- **`pow(&mut self, x: &BigImpl)`**                        
- **`div(&mut self, g: &Self)`**            
- **`get(&self) -> Self`**            
- **`set(&mut self, g: &Self)`**             
- **`to_bytes(&self) -> &[u8]`**
- **`from_bytes(bytes: &[u8]) -> Self`**

For pairing friendly curves, another trait is neeeded, namely the `PairingEngine` trait that specifies alternate groups and defines a pairing operation.

**PairingEngine**<br>
- **`type G2: DlGroup`**
- **`type G3: DlGroup`** <br><br>
- **`fn pair(g1: &Self::G2, g2: &Self) -> Self::G3`**
- **`fn ddh(g1: &Self::G2, g2: &Self, g3:&Self::G2, g4:&Self) -> bool`**

<br>
Now we want to be able to use pairing friendly and non pairing friendly curves interchangeably as long as pairings aren't needed. Therefore we need another trait that defines whether the corresponding curve is pairing friendly: <br><br>


**DlDomain** <br>
- **`is_pairing_friendly() -> bool`**



