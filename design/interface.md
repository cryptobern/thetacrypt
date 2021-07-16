# Threshold API
This document presents the abstract interfaces for our threshold cryptography library.

**Parameters**
- ... (empty)

**VerificationKey**
- ... (empty)

**PublicKey**
- **publicValue**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; public key value
- **verificationKey**: verification key (`VerificationKey` instance)
- **k**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; threshold
- **params**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;the domain parameters (`Parameters` instance)

**PrivateKey** extends **PublicKey**
- **id**: key identifier
- **xi**: private key share

**Share**
- **id**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; share identifier
- **label**:&nbsp;&nbsp;&nbsp;label used to show which shares belong together
- **data**:&nbsp;&nbsp;&nbsp;&nbsp;share value

**Ciphertext**
- **label**:&nbsp;&nbsp;&nbsp;&nbsp; label describing the message content
- **msg**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; encrypted message

**SignedMessage**
- **sig**:&nbsp;&nbsp; signature
- **msg**: message

<br><br>

# KeyGenerator

**`KeyGenerator::generateKeys(k: u8, n: u8, group: Group) -> (PublicKey, Vec<PrivateKey>)`**<br>
<br><br>


# ThresholdCoin

**`ThresholdCoin::createShare(cname: String, privateKey: PrivateKey) -> Share`**<br>

**`ThresholdCoin::verifyShare(share: Share, cname: String, publicKey: PublicKey) -> bool`**<br>

**`ThresholdCoin::assemble(shares: Vec<Share>) -> u8`**<br><br>

# ThresholdCipher


**`ThresholdCipher::encrypt(msg: Vec<u8>, label: Vec<u8>, pk: PublicKey) -> Ciphertext`**<br>

**`ThresholdCipher::verifyCiphertext(ct: Ciphertext, pk: PublicKey) -> bool`**<br>

**`ThresholdCipher::decrypt(ct: Ciphertext, sk: PrivateKey) -> Share`**<br>

Method probably needs renaming (partiallyDecrypt?)

**`ThresholdCipher::verifyShare(sh: Share, ct: Ciphertext, pk: PublicKey) -> bool`**<br>

**`ThresholdCipher::assemble(ct: Ciphertext, shares: Vec<Share>]) -> Vec<u8>`**<br><br>

# ThresholdSignature 

**`ThresholdSignature::sign(msg: Vec<u8>, sk: PrivateKey) -> Share`**<br>

Method probably needs renaming (partiallySign?)

**`ThresholdSignature::verifyShare(share: Share, pk: PublicKey, msg: Vec<u8>) -> bool`**<br>

**`ThresholdSignature::assemble(shares: Vec<Share>, msg: Vec<u8>) -> bool`**<br>

**`ThresholdSignature::verify(sig: SignedMessage) -> bool`**<br>
