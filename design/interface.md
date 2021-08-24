# Threshold Crypto Library API
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

**CoinShare**
- **id**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; share identifier
- **label**:&nbsp;&nbsp;&nbsp;label used to show which shares belong together
- **data**:&nbsp;&nbsp;&nbsp;&nbsp;share value

**DecryptionShare**
- **id**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; share identifier
- **label**:&nbsp;&nbsp;&nbsp;label used to show which shares belong together
- **data**:&nbsp;&nbsp;&nbsp;&nbsp;share value

**SignatureShare**
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

**`KeyGenerator::generateKeys(uint8_t k, uint8_t n, Parameters params) -> (PublicKey, vector<PrivateKey>)`**<br>
<br><br>


# ThresholdCoin

**`ThresholdCoin::createShare(string cname, PrivateKey privateKey) -> CoinShare`**<br>

**`ThresholdCoin::verifyShare(CoinShare share, string cname, PublicKey publicKey) -> bool`**<br>

**`ThresholdCoin::assemble(vector<CoinShare> shares) -> uint8_t`**<br><br>

# ThresholdCipher


**`ThresholdCipher::encrypt(vector<uint8_t> msg, vector<uint8_t> label, PublicKey pk) -> Ciphertext`**<br>

**`ThresholdCipher::verifyCiphertext(Ciphertext ct, PublicKey pk) -> bool`**<br>

**`ThresholdCipher::partialDecrypt(Ciphertext ct, PrivateKey sk) -> DecryptionShare`**<br>

**`ThresholdCipher::verifyShare(DecryptionShare share, Ciphertext ct, PublicKey pk) -> bool`**<br>

**`ThresholdCipher::assemble(Ciphertext ct, vector<DecryptionShare> shares) -> vector<uint8_t>`**<br><br>

# ThresholdSignature 

**`ThresholdSignature::partialSign(vector<uint8_t> msg, PrivateKey sk) -> SignatureShare`**<br>

**`ThresholdSignature::verifyShare(SignatureShare share, PublicKey pk, vector<uint8_t> msg) -> bool`**<br>

**`ThresholdSignature::assemble(vector<SignatureShare> shares, vector<uint8_t> msg) -> bool`**<br>

**`ThresholdSignature::verify(SignedMessage sig, PublicKey pk) -> bool`**<br>
