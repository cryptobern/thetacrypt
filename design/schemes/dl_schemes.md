# Threshold DL Schemes Implementation

Operating on a cyclic group *G* of order *q* with generator *g*. The group G can be either a prime order subgroup of Z∗ or an elliptic curve group (except for the GDH threshold scheme) and its group operation is written in multiplicative form. The following objects will be used in the presented threshold schemes:

**Group** implements **Parameters**
- **q: `BIG`**: group order
- **g**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; generator

**Fp_Group** implements **Group**
- **p: `BIG`**: modulus
- **q: `BIG`**: group order
- **g: `BIG`**: generator
<br><br>

**EC_Group** imlements **Group**
- **name: `String`**:&nbsp;&nbsp; curve name
- **q: `BIG`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; group order
- **g: `ECP`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; generator
<br><br>

**DL_VerificationKey** implements **VerificationKey**
- **key: `Vec<BIG>`**: Verification key value
<br><br>

**DL_PublicKey** implements **PublicKey**
- **y: `BIG`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; public key value
- **verificationKey: `DL_VerificationKey`**:&nbsp; verification key
- **k: `u8`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; threshold
- **group: `Group`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; the underlying group
<br><br>

**DL_PrivateKey** extends **DL_PublicKey** implements **PrivateKey** 
- **id: `u32`**:&nbsp;&nbsp; key identifier
- **xi: `BIG`**: private key share

<br>

**`interpolate(shares: Vec<Share>) -> BIG`** <br>
`z = 1`<br>
`for each share s in shares do`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`di = s.data^lag_coeff(s.id)`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`z = z*di`<br>
`return z`<br><br>

# DL_KeyGenerator
Implementation of abstract interface `KeyGenerator`. The following method generates public/private keys that can be used for all presented schemes.

**`DL_KeyGenerator::generate_keys(k: u8, n: u8, group: Group) -> (DL_PublicKey, Vec<DL_PrivateKey>)`**<br>
`x = random(2, group.q-1)` <br> 
`y = group.g^x` <br>
`ĝ = group.g^random(2, group.q-1)` <br>
`{x₁, .. xₙ} = ShareSecret(x, k, n)` <br>
`verificationKey = {group.g^x₁,...,group.g^xₙ}` <br>
`pk = DL_PublicKey(y, verificationKey, ĝ)`<br>
`secrets = []`<br>
`for each xi in {x₁, .. xₙ} do`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`secrets.push(DL_PrivateKey(i, xi, y, verificationKey, ĝ))`<br>
`return (pk, secrets)`<br>
<br><br>


# CKS05_ThresholdCoin
[Reference (p. 22)](https://link.springer.com/content/pdf/10.1007/s00145-005-0318-0.pdf) <br>
Implementation of abstract interface `ThresholdCoin`.

**Intuition**<br>
The value of a coin named *C* is obtained by hashing *C*&nbsp;to obtain ĉ *ϵ G*, then raising ĉ to the secret key *x* to obtain ĉ' and finally hashing ĉ' to obtain the value F(C) ϵ {0,1}. The secret key *x* is shared using Shamir's secret sharing (to obtain secret shares xi) and instead of calculating ĉ' = ĉ^x, shares ĉ^xi can be combined to obtain ĉ' by interpolation in the exponent.

**Needed hash functions:**<br>
```H(cname)```: Hashes a coin name to a group element<br>
```H1(g0, g1, g2, g3, g4, g5)```: Hashes six group elements to an element in [0, q-1]<br>
```H2(g0)```: Hashes a group element to a single bit 0/1<br>
<br>

**Needed objects:**<br>

**CKS05_CoinShare** implements **CoinShare**
- **id**: share identifier
- **data**: coin share
- **c**:  zkp parameter
- **z**:  zkp parameter

**Scheme:** <br>
**`CKS05_ThresholdCoin::createShare(cname: String, sk: DL_PrivateKey) -> CKS05_CoinShare`**<br>
`ĉ = H(cname)`<br>
`data = ĉ^sk.xi`<br>
`s = random(2, sk.group.q-1)` <br>
`h = sk.group.g^s` <br>
`ĥ = (sk.ĝ)^s` <br>
`c = H1(sk.group.g, sk.verificationKey[sk.id], h, ĉ, data, ĥ)` <br>
`z = s + sk.xi*c` <br>
`return CKS05_CoinShare(sk.id, data, c, z)`<br><br>

**`CKS05_ThresholdCoin::verifyShare(share: CKS05_CoinShare, cname: String, pk: DL_PublicKey) -> bool`**<br>
`ĉ = H(cname)`<br>
`h = pk.group.g^share.z / pk.verificationkey[share.id]^share.c`<br>
`ĥ = pk.ĝ^share.z / share.data^share.c`<br>
`return c == H1(pk.group.g, pk.verificationKey[share.id], h, ĉ, share.data, ĥ)`<br><br>

**`CKS05_ThresholdCoin::assemble(shares: Vec<CKS05_CoinShare>, pk: PublicKey) -> u8`**<br>
`if k > shares.size then`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`return null`<br>
`ĉ' = interpolate(shares)`<br>
`return H2(ĉ')`<br><br><br>

# SG02_ThresholdCipher
[Reference](https://link.springer.com/content/pdf/10.1007/s00145-001-0020-9.pdf)<br>
Implementation of abstract interface `ThresholdCipher`.

**Needed hash functions:**<br>
```H1(m0, m1, g0, g1, g2, g3)```: Hashes two bit strings and four group elements to an element in [0, q-1]<br>
```H2(g0, g1, g2)```: Hashes three group elements to a single group element<br>
<br>

**SG02_DecryptionShare** implements **DecryptionShare**
- **id**: share identifier
- **data**: decryption share
- **ei**: zkp parameter
- **fi**:&nbsp; zkp parameter

**SG02_Ciphertext** implements **Ciphertext**
- **c_k**: encrypted symmetric key
- **label**:&nbsp;&nbsp;&nbsp;&nbsp; label
- **u**:&nbsp;&nbsp;&nbsp;&nbsp; interpolation parameter needed to reconstruct symmetric key
- **û**:&nbsp;&nbsp;&nbsp;&nbsp; zkp parameter
- **e**:&nbsp;&nbsp;&nbsp;&nbsp; zkp parameter
- **f**:&nbsp;&nbsp;&nbsp;&nbsp; zkp parameter
- **msg**:&nbsp;&nbsp;&nbsp;&nbsp; encrypted message

**Scheme:**

**`SG02_ThresholdCipher::encrypt(m: bytes, pk: DL_PublicKey, label:Vec<u8>) -> SG02_Ciphertext`**<br>
`k = gen_symm_key()`<br>
`c = symm_enc(m, k)`<br>
`r = random(2, pk.group.q-1)` <br>
`z = pk.y^r` <br>
`c_k = k xor z` <br>
`s = random(2, pk.group.q-1)` <br>
`u = pk.group.g^r` <br>
`w = pk.group.g^s` <br>
`û = pk.ĝ^r` <br>
`ŵ = pk.ĝ^s` <br>
`e = H1(c_k, L, u, w, û, ŵ)` <br>
`f = s + re` <br>
`return SG02_Ciphertext(c_k, label, u, û, e, f, c)`<br><br>

**`SG02_ThresholdCipher::verifyCiphertext(ct: SG02_Ciphertext, pk: DL_PublicKey) -> bool`**<br>
`w = g^ct.f / ct.u^ct.e`<br>
`ŵ = pk.ĝ^ct.f / ct.û^ct.e`<br>
`return ct.e == H1(ct.c_k, ct.label, ct.u, w, ct.û, ŵ)`<br>

**`SG02_ThresholdCipher::decrypt(ct: SG02_Ciphertext, sk: DL_PrivateKey) -> SG02_DecryptionShare`**<br>
`data = ct.u^sk.xi`<br>
`si = random(2, sk.group.q-1)` <br>
`ûi = ct.u^si` <br>
`ĥi = sk.group.g^si` <br>
`ei = H2(data, ûi, ĥi)` <br>
`fi = si + sk.xi*ei` <br>
`return SG02_DecryptionShare(sk.id, data, ei, fi)`<br><br>

**`SG02_ThresholdCipher::verifyShare(sh: SG02_DecryptionShare, ct: SG02_Ciphertext, pk: DL_PublicKey) -> bool`**<br>
`ûi = ct.u^sh.fi / sh.data^sh.ei`<br>
`ĥi = pk.group.g^sh.fi / pk.verificationKey[sh.id]^sh.ei`<br>
`return ct.e == H2(sh.data, ûi, ĥi)`<br><br>

**`SG02_ThresholdCipher::assemble(ct: SG02_Ciphertext, shares: Vec<SG02_DecryptionShare>, pk: PublicKey) -> Vec<u8>`**<br>
`if k > shares.size then`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`return null`<br>
`z = interpolate(shares)`<br>
`k = ct.c_k xor z`<br>
`m = symm_dec(ct.c, k)`<br>
`return m`<br><br>

# BZ03_ThresholdCipher
[Reference](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.119.1717&rep=rep1&type=pdf)<br>
Implementation of abstract interface `ThresholdCipher`.

**Background** <br>
DDH problem: Given (g, g^a, g^b, g^c) ϵ G where G = < g > is a group of prime order q and a,b,c are uniformly chosen at random from {1,..,q-1}, one is asked to decide whether c = ab. <br>
CDH problem: One is asked to compute g^ab given (g, g^a, g^b) <br>
*G* is called a Gap Diffie-Hellman group if there exists an efficient algorithm for solving the DDH problem, but not for the CDH problem. For this scheme we will need a GDH group which can be constructed using a bilinear map on supersingular elliptic curves.<br>
<br>
**Needed helper methods:**<br>
```ê(g0, g1)```: Determines whether a given tuple (g, g^a, g^b, g^c) is a DH tuple by checking whether ê(g, g^c) = ê(g^a, g^b)<br>
```G(g0)```: Hashes a group element to a bit string<br>
```H(g0, m)```: Hashes a group element and a bit string to a single group element<br>
<br>

**Needed objects:**<br>

**BZ03_DecryptionShare** implements **DecryptionShare**
- **id**: share identifier
- **label**: label identifying which shares belong together
- **data**: decryption share

**BZ03_Ciphertext** implements **Ciphertext**
- **c_k**: encrypted symmetric key
- **label**:&nbsp;&nbsp;&nbsp;&nbsp; label
- **u**:&nbsp;&nbsp;&nbsp;&nbsp; interpolation parameter needed to reconstruct symmetric key
- **û**:&nbsp;&nbsp;&nbsp;&nbsp; zkp parameter
- **msg**:&nbsp;&nbsp;&nbsp;&nbsp; encrypted message


**Scheme**


**`BZ03_ThresholdCipher::encrypt(msg: Vec<u8>, pk: DL_PublicKey, label:string) -> BZ03_Ciphertext`**<br>
`k = gen_symm_key()`<br>
`c = symm_enc(msg, k)`<br>
`r = random(2, q-1)`<br>
`u = g^r`<br>
`c_k = G(pk.y^r) xor k`<br>
`û = H(u, c)^r`<br>
`return BZ03_Ciphertext(c_k, label, u, û, c)`<br><br>

**`BZ03_ThresholdCipher::verifyCiphertext(ct: BZ03_Ciphertext) -> bool`**<br>
`h = H(ct.u, ct.msg)`<br>
`return ê(g, ct.û) == ê(ct.u, h)`<br><br>

**`BZ03_ThresholdCipher::decrypt(ct: BZ03_Ciphertext, sk: DL_PrivateKey) -> BZ03_DecryptionShare`**<br>
`if verify_ciphertext(ct) == false then`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`return null`<br>
`ui = ct.u^xi`<br>
`return BZ03_DecryptionShare(sk.id, ui)`<br><br>

**`BZ03_ThresholdCipher::verifyShare(ct: BZ03_Ciphertext, sh: BZ03_DecryptionShare, pk: PublicKey) -> bool`**<br>
`return ê(g, sh.ui) == ê(ct.u, pk.verificationKey[sh.id])`<br><br>

**`BZ03_ThresholdCipher::assemble(ct: BZ03_Ciphertext, shares: [BZ03_DecryptionShare]], pk: PublicKey) -> Vec<u8>`**<br>
`if k > shares.size then`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`return null`<br>
`z = interpolate(shares)`<br>
`k = ct.c_k xor G(z)`<br>
`m = symm_dec(ct.msg, k)`<br>
`return m`<br><br>

# BLS04_ThresholdSignature 
[Reference](https://gitlaassembleb.assembleinf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/papers/short_signatures_weil_pairing-joc04.pdf)<br>
Implementation of abstract interface `ThresholdSignature`.
Again, a GDH group is needed for the following scheme.

**Needed helper methods:**<br>
```ê(g0, g1)```: Determines whether a given tuple (g, g^a, g^b, g^c) is a DH tuple by checking whether ê(g, g^c) = ê(g^a, g^b)<br>
```H(m)```: Hashes a bit string to a single group element<br>
<br>

**Needed objects:**<br>

**BLS04_SignatureShare** implements **SignatureShare**
- **id**: share identifier
- **label**: label specifying which shares belong together
- **data**: signature share

**Scheme**

**`BLS04_ThresholdSignature::sign(msg: Vec<u8>, label: Vec<u8>, sk: DL_PrivateKey) -> BLS04_SignatureShare`**<br>
`data = H(msg)^sk.xi`<br>
`return BLS04_SignatureShare(sk.id, label, data)`<br><br>

**`BLS04_ThresholdSignature::verifyShare(share: BLS04_SignatureShare, pk: DL_PublicKey, msg: Vec<u8>) -> bool`**<br>
`return ê(pk.group.g, pk.verificationKey[share.id]) == ê(H(msg), share.data)`<br><br>

**`BLS04_ThresholdSignature::assemble(shares: Vec<BLS04_SignatureShare>, msg: Vec<u8>) -> SignedMessage`**<br>
`if k > shares.size then`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`return null`<br>
`sig = interpolate(shares)`<br>
`return SignedMessage(sig, msg)`<br><br>

**`BLS04_ThresholdSignature::verify(sig: SignedMessage, pk: DL_PublicKey) -> bool`**<br>
`return ê(pk.group.g, pk.y) == ê(H(sig.msg), sig.sig)`<br><br>
