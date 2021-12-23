# Threshold RSA Schemes Implementation

**RSA_Params** implements **Parameters**
- **length: `int`**: bit length of p and q

**RSA_VerificationKey** implements **VerificationKey**
- **v: `BIG`**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 
- **vi: `Vec<BIG>`**&nbsp;&nbsp;&nbsp; 
- **u: `BigInt`**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<br><br>

**RSA_PublicKey** implements **PublicKey**
- **N: `BigInt`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; modulus
- **e: `BigInt`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;exponent
- **vk: `RSA_VerificationKey`**:&nbsp; verification key
- **n: `u32:`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;number of keys
<br><br>

**RSA_PrivateKey** extends **RSA_PublicKey** implements **PrivateKey** 
- **id: `u32`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  key identifier
- **xi: `BIG`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;private key share
- **N: `BigInt`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;modulus
- **e: `BigInt`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;exponent
- **vk: `RSA_VerificationKey`**:&nbsp; verification key
- **n: `u32:`**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; number of keys

<br>

**Helper methods**

	interpolate(shares: Vec<Share>) -> BIG
		z = 1
		for each share s in shares do
			di = s.data^lag_coeff(s.id)
			z = z*di
		return z

	share_secret(x: BIG, n: u32, m: BIG) -> Vec<BIG>
		let coeff: vec<BIG>
		let shares: vec<BIG>
		coeff.push(x)
		for i in 1,...,m-1 do
			coeff.push(random(0, m-1))
		for i in 0,...,n do
			shares.push((eval_pol(i, coeff) * n!^(-1)) % m)
		return shares


L(n) = bit-length of n <br>
L1 = bit-length of output of hash function H' <br>
Let $`Q_n`$ be the subgroup of squares in $`Z_n^{*}`$.

# RSA_KeyGenerator
Implementation of abstract interface `KeyGenerator`. The following method generates public/private keys that can be used for all presented schemes.

	RSA_KeyGenerator::generate_keys(k: u8, n:u8, params:Parameters) -> (RSA_PublicKey, Vec<RSA_PrivateKey>)
		choose random prime p of length params.length such that p = 2p' + 1 with p' prime
		choose random prime q of length params.length such that q = 2q' + 1 with q' prime
		e = random_prime()
		N = pq
		d = mod_inv(e, phi(N))
		m = p' * q'
		{x₁, .. xₙ} = share_secret(d, k, n)
		v = random_element(Qn)
		choose random element u in Zn with Jacobi symbol (u|n) = -1
		verificationKey = RSA_VerificationKey(v, {v^x₁,...,v^xₙ}, u)
		pk = RSA_PublicKey(N, e, verificationKey, n)
		secrets = []
		for each xi in {x₁, .. xₙ} do
			secrets.push(DL_PrivateKey(i, xi, n)
		sk = RSA_PrivateKey(N, e)
		return (pk, secrets)


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
`h = H(msg)`<br>
`if (h|sk.n) = 1 then`<br>
`	   x = h`<br>
`else`<br>
`      h = h * sk.vk.u^sk.e`<br>
`si = x^(2*xi)`<br>
`x* = x^4`<br>
`r = random(0, 2^(L(n) + 2*L1) - 1)`<br>
`v' = v^r`<br>
`x' = x^r`<br>
`c = H'(v, x*, vi, si^2, v', x')` <br>
`z = xi*c + r`<br>
`return SH00_SignatureShare(i, label, si z, c)`<br><br>


**`SH00_ThresholdSignature::verifyShare(share: SH00_SignatureShare, pk: DL_PublicKey, msg: Vec<u8>) -> bool`**<br>
`x* = x^4`<br>
`return share.c == H'(pk.vk.v, x*, pk.vk.vi, share.data^2, pk.vk.v^z*pk.vk.vi^(-c), x*^z*share.data^(-2c))`<br><br>

**`SH00_ThresholdSignature::assemble(shares: Vec<SH00_SignatureShare>, msg: Vec<u8>) -> SignedMessage`**<br>
`if k > shares.size then`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`return null`<br>
`x = H(msg)` <br>
`w = 1`<br>
`for each share s in shares do`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`di = s.data^(2*lag_coeff(s.id))`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`w = w*di`<br>
`a,b = ext_euclid(e', 4)`<br>
`y = w^a*x^b`<br>
`return SignedMessage(y, msg)`<br><br>

**`SH00_ThresholdSignature::verify(sig: SignedMessage, pk: DL_PublicKey) -> bool`**<br>
`return sig.sig^pk.e == H(sig.msg)`<br><br>
