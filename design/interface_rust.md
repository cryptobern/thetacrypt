# Threshold Crypto Library API (RUST Version)

In Rust, no such concept as inheritance exists. Instead, the language uses the concept of "composition over inheritance," which means we have to structure the API differently.

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

### Threshold Cipher

**CipherPublicKey**<br>
- **`encrypt(&self, msg: Vec<u8>, label: Vec<u8>) -> impl Ciphertext`**
- **`verify_share(&self, sh: impl Share, ct: impl Ciphertext) -> bool`**
- **`verify_ciphertext(&self, ct: impl Ciphertext) -> bool`**
- **`assemble(ct: impl Ciphertext, shares: Vec<impl Share>]) -> Vec<u8>`**

**CipherPrivateKey**<br>
- **`partial_decrypt(&self, ct: impl Ciphertext) -> impl Share`**

### Threshold Signature

**SignaturePublicKey**<br>
- **`verify(&self, sig: impl SignedMessage) -> bool`**
- **`verify_share(&self, share: impl Share, msg: Vec<u8>) -> bool`**
- **`assemble(shares: Vec<impl Share>, msg: Vec<u8>) -> bool`**

**SignaturePrivateKey**<br>
- **`partial_sign(&self, msg: Vec<u8>) -> impl Share`**

### Threshold Coin

**CoinPublicKey**<br>
- **`verify_share(&self, share: impl Share, cname: String) -> bool`**
- **`assemble(shares: Vec<impl Share>) -> u8`**

**CoinPrivateKey**<br>
- **`create_share(&self, cname: String) -> impl Share`**
