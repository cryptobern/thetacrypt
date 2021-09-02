# Threshold Crypto Library API (RUST Version)

In Rust, no such concept as inheritance exists. Instead, the language uses the concept of "composition over inheritance," which means we have to structure the API differently. In this document, RUST notation and datatypes will be used.

## Traits

**Share** <br>
- **`get_id(&self) -> u8`**
- **`get_data(&self) -> Vec<u8>`**

**Ciphertext**<br>
- **`get_label(&self)`**
- **`get_message(&self)`**

**SignedMessage**<br>
- **`get_signature(&self)`**
- **`get_message(&self)`**

**PublicKey** <br>

**PrivateKey** <br>
- **`get_public_key(&self)`**

**DL_Group** <br>
- **`get_generator(&self) -> DL_GroupElement`**
- **`get_order(&self) -> BIG`**

**DL_GroupElement**<br>
- **`new() -> Self;`** returns generator                            
- **`new_big(x: &BIG) -> Self;`** returns generator^x
- **`new_rand(rng: &mut impl RAND) -> Self;`** returns random element in group
- **`mul(&mut self, g: &Self);`**            
- **`pow(&mut self, x: &BIG);`**                        
- **`div(&mut self, g: &Self);`**            
- **`get(&self) -> Self;`**            
- **`set(&mut self, g: &Self);`**             
- **`to_bytes(&self) -> &[u8];`**
- **`from_bytes(&self, bytes: &[u8]);`**

**BigInt** <br>
- **`new() -> Self`**
- **`new_big(y: &Self::DataType) -> Self`**
- **`new_ints(a: &[Chunk]) -> Self`**
- **`new_copy(y: &Self) -> Self`**
- **`from_bytes(bytes: &[u8]) -> Self`**
- **`rmod(&mut self, y: &Self)`**
- **`rmul(&mut self, y: &Self, q: &Self)`**
- **`add(&mut self, y: &Self)`**
- **`to_bytes(&self) -> &[u8]`**
- **`to_string(&self) -> &str`**

**KeyGenerator**<br>
- **`generate_keys(k: &u8, n: &u8, rng: &mut impl RAND, domain: &Domain, scheme: &Scheme) -> Vec<Box<impl PrivateKey>>`**

**ThresholdCoin**<br>
- **`create_share(cname: String, sk: &PrivateKey, &sk: PrivateKey) -> impl Share`**
- **`verify_share(share: impl Share, cname: String, &pk: PublicKey) -> bool`**
- **`assemble(shares: Vec<impl Share>, &pk: PublicKey) -> u8`**

**ThresholdCipher**<br>
- **`encrypt(msg: Vec<u8>, label: Vec<u8>, &pk: PublicKey) -> impl Ciphertext`**
- **`verify_ciphertext(ct: impl Ciphertext, &pk: PublicKey) -> bool`**
- **`partial_decrypt(ct: impl Ciphertext, &sk: PrivateKey) -> impl Share`**
- **`verify_share(sh: impl Share, ct: impl Ciphertext, &pk: PublicKey) -> bool`**
- **`assemble(ct: impl Ciphertext, shares: Vec<impl Share>], &pk: PublicKey) -> Vec<u8>`**

**ThresholdSignature**<br>
- **`verify(sig: impl SignedMessage, &pk: PublicKey) -> bool`**
- **`partial_sign(msg: Vec<u8>, &sk: PrivateKey) -> impl Share`**
- **`verify_share(share: impl Share, msg: Vec<u8>, &pk: PublickKey) -> bool`**
- **`assemble(shares: Vec<impl Share>, msg: Vec<u8>, &pk: PublicKey) -> bool`**