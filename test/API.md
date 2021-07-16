# Threshold API

**PublicKey**
- **publicValue**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; public key value
- **verificationKey**: verification key consisting of n values vk[i] = g^xi
- **params**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; implementation specific parameters

**PrivateKey** extends **PublicKey**
- **id**: key identifier
- **xi**: private key share

**Share**
- **id**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; share identifier
- **di**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; share value
- **params**:  implementation specific parameters

**Ciphertext**
- **label**:&nbsp;&nbsp;&nbsp;&nbsp; label
- **msg**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; encrypted message
- **params**: implementation specific parameters

**SignedMessage**
- **sig**:&nbsp;&nbsp; signature
- **msg**: message
<br><br>

# KeyManager

The **`KeyManager`** class creates and updates keys (for later versions).<br> 

**`KeyManager::generateKeys(k: u8, n: u8, rng: RAND) -> (PublicKey, Vec<PrivateKey>)`**<br>
<br><br>


# ThresholdCoin

**`ThresholdCoin::createShare(cname: String, privateKey: PrivateKey) -> Share`**<br>

**`ThresholdCoin::verifyShare(share: Share, cname: String, publicKey: PublicKey) -> bool`**<br>

**`ThresholdCoin::assemble(shares: Vec<Share>) -> u8`**<br><br>

# ThresholdCipher


**`ThresholdCipher::encrypt(msg: Vec<u8>, label: Vec<u8>, pk: PublicKey) -> Ciphertext`**<br>

**`ThresholdCipher::verifyCiphertext(ct: Ciphertext, pk: PublicKey) -> bool`**<br>

**`ThresholdCipher::createShare(ct: Ciphertext, sk: PrivateKey) -> Share`**<br>

**`ThresholdCipher::verifyShare(sh: Share, ct: Ciphertext, pk: PublicKey) -> bool`**<br>

**`ThresholdCipher::assemble(ct: Ciphertext, shares: Vec<Share>]) -> Vec<u8>`**<br><br>

# ThresholdSignature 

**`ThresholdSignature::sign(msg: Vec<u8>, sk: PrivateKey) -> Share`**<br>

**`ThresholdSignature::verifyShare(share: Share, pk: PublicKey, msg: Vec<u8>) -> bool`**<br>

**`ThresholdSignature::assemble(shares: Vec<Share>, msg: Vec<u8>) -> bool`**<br>

**`ThresholdSignature::verify(sig: SignedMessage) -> bool`**<br>
