# Threshold RSA Schemes Implementation

**RSA_Params** implements **Parameters**
- **length: `int`**: bit length of p and q

**RSA_VerificationKey** implements **VerificationKey**
- **v: `BIG`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; base value
- **key: `Vec<BIG>`**: key value
<br><br>

**RSA_PublicKey** implements **PublicKey**
- **N: `BigInt`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; modulus
- **e: `BigInt`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; exponent
- **verificationKey: `RSA_VerificationKey`**:&nbsp; verification key
- **n: `u32:`**: number of keys
<br><br>

**RSA_PrivateKey** extends **RSA_PublicKey** implements **PrivateKey** 
- **id: `u32`**: key identifier
- **xi: `BIG`**: private key share
- **n: `u32:`**: number of keys

<br>

**`interpolate(shares: Vec<Share>) -> BIG`** <br>
`z = 1`<br>
`for each share s in shares do`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`di = s.data^lag_coeff(s.id)`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`z = z*di`<br>
`return z`<br><br>


L(n) = bit-length of n <br>
L1 = bit-length of output of hash function H'

Let $`Q_n`$ be the subgroup of squares in $`Z_n^{*}`$.

# RSA_KeyGenerator
Implementation of abstract interface `KeyGenerator`. The following method generates public/private keys that can be used for all presented schemes.

**`RSA_KeyGenerator::generate_keys(k: u8, n:u8, params:Parameters) -> (RSA_PublicKey, Vec<RSA_PrivateKey>)`** <br>
`p = random_prime(params.length)`<br>
`q = random_prime(params.length)`<br>
`e = random_prime()`<br>
`N = pq`<br>
`d = mod_inv(e, phi(N))`<br>
`{x₁, .. xₙ} = ShareSecret(d, k, n)`<br>
`v = random_element(Qn)`<br>
`verificationKey = RSA_VerificationKey(v, {v^x₁,...,v^xₙ})` <br>
`pk = RSA_PublicKey(N, e, verificationKey, n)`<br>
`secrets = []`<br>
`for each xi in {x₁, .. xₙ} do`<br>
`      secrets.push(DL_PrivateKey(i, xi, n)`<br>
`sk = RSA_PrivateKey(N, e)`<br>
`return (pk, secrets)`<br>


# SH00_ThresholdSignature
[reference](https://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf)<br>
Implementation of abstract interface `ThresholdSignature`.

**SH00_SignatureShare** implements **SignatureShare**
- **id**: share identifier
- **label**: label specifying which shares belong together
- **data**: share value
- **z**: proof of correctness parameter
- **c**: proof of correctness parameter 
<br><br>

**Needed helper methods:**<br>
```H(m)```: Hashes a single bit string to a single value in $`\mathbb{Z}_n^{*}`$<br>
```H'(a, b, c, d, e, f)```: Hashes six bit strings to a single value in $`\mathbb{Z}_n^{*}`$<br>
<br>


**Scheme**<br>

**`SH00_ThresholdSignature::sign(msg: Vec<u8>, label: Vec<u8>, sk: RSA_PrivateKey) -> SH00_SignatureShare`**<br>
`x = H(msg)`<br>
`delta = sk.n!`<br>
`si = x^(2*delta*xi)`<br>
`u = x^(4*delta)`<br>
`r = random(0, 2^(L(n) + 2*L1) - 1)`<br>
`v' = v^r`<br>
`u' = u^r`<br>
`c = H'(v, u, vi, xi^2, v', u)` <br>
`z = xi*c + r`<br>
`return SH00_SignatureShare(i, label, si z, c)`<br><br>


**`SH00_ThresholdSignature::verifyShare(share: SH00_SignatureShare, pk: DL_PublicKey, msg: Vec<u8>) -> bool`**<br>
`u = x^(4*pk.n!)`<br>
`return share.c == H'(pk.vk.v, u, pk.vk.vi, xi^2, pk.vk.v^z*pk.vk.vi^(-c), u^z*xi^(-2c))`<br><br>

**`SH00_ThresholdSignature::assemble(shares: Vec<SH00_SignatureShare>, msg: Vec<u8>) -> SignedMessage`**<br>
`if k > shares.size then`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`return null`<br>
`x = H(msg)`
`w = 1`<br>
`for each share s in shares do`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`di = s.data^(2*lag_coeff(s.id))`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`w = w*di`<br>
`e' = 4*delta^2`<br>
`a,b = ext_euclid(e', e)`<br>
`y = w^a*x^b`<br>
`return SignedMessage(y, msg)`<br><br>

**`SH00_ThresholdSignature::verify(sig: SignedMessage, pk: DL_PublicKey) -> bool`**<br>
`return sig.sig^pk.e == H(sig.msg)`<br><br>
