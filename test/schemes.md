# Threshold Schemes Summary

Operating on a cyclic group *G* of order *q* with generator *g*. The group G can be either a discrete logarithm or an elliptic curve group (except for the GDH threshold scheme) and its group operation is written in multiplicative form. The following objects will be used in the presented threshold schemes:

**public_key**
- **y**:&nbsp;&nbsp;&nbsp;public key value
- **vk**: verification key consisting of n values vk[i] = g^xi
- **ĝ**:&nbsp;&nbsp;&nbsp;alternate generator

**private_key** 
- **id**: key identifier
- **xi**: private key share
- **y**:&nbsp;&nbsp;public key value
- **vk**: verification key consisting of n values vk[i] = g^xi
- **ĝ**:&nbsp;&nbsp;alternate generator

**coin_share**
- **id**: share identifier
- **di**: coin share
- **c**:  zkp parameter
- **z**:  zkp parameter

**ciphertext**
- **c_k**: encrypted symmetric key
- **L**:&nbsp;&nbsp;&nbsp;&nbsp; label
- **u**:&nbsp;&nbsp;&nbsp;&nbsp; interpolation parameter needed to reconstruct symmetric key
- **û**:&nbsp;&nbsp;&nbsp;&nbsp; zkp parameter
- **e**:&nbsp;&nbsp;&nbsp;&nbsp; zkp parameter
- **f**:&nbsp;&nbsp;&nbsp;&nbsp; zkp parameter
- **c**:&nbsp;&nbsp;&nbsp;&nbsp; encrypted message

**decryption_share**
- **id**: share identifier
- **ui**: decryption share
- **ei**: zkp parameter
- **fi**:&nbsp; zkp parameter

**partial_signature**
- **id**:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; share identifier
- **si**:&nbsp;&nbsp;&nbsp;&nbsp; &nbsp;partial signature

**signed_message**
- **sig**:&nbsp;&nbsp; signature
- **msg**: message
<br>

# Key Generation
The following method generates public/private keys that can be used for all presented schemes.

**`generate_keys(k, n)`**<br>
`x = random(2, q-1)` <br> 
`y = g^x` <br>
`ĝ = g^random(2, q-1)` <br>
`{x₁, .. xₙ} = ShareSecret(x, k, n)` <br>
`vk = {g^x₁,...,g^xₙ}` <br>
`pk = public_key(y, vk, ĝ)`<br>
`secrets = []`<br>
`for each xi in {x₁, .. xₙ} do`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`secrets.push(private_key(i, xi, y, vk, ĝ))`<br>
`return pk, secrets`<br>
<br><br>


# Threshold Coin
[Reference (p. 22)](https://link.springer.com/content/pdf/10.1007/s00145-005-0318-0.pdf)

**Intuition**<br>
The value of a coin named *C* is obtained by hashing *C*&nbsp;to obtain ĉ *ϵ G*, then raising ĉ to the secret key *x* to obtain ĉ' and finally hashing ĉ' to obtain the value F(C) ϵ {0,1}. The secret key *x* is shared using Shamir's secret sharing (to obtain secret shares xi) and instead of calculating ĉ' = ĉ^x, shares ĉ^xi can be combined to obtain ĉ' by interpolation in the exponent.

**Needed hash functions:**<br>
```H(coin_name)```: Hashes a coin name to a group element<br>
```H1(g0, g1, g2, g3, g4, g5)```: Hashes six group elements to an element in [0, q-1]<br>
```H2(g0)```: Hashes a group element to a single bit 0/1<br>
<br>

**Scheme:** <br>
**`create_coin_share(coin_name: string, sk: private_key)`**<br>
`ĉ = H(coin_name)`<br>
`di = ĉ^sk.xi`<br>
`s = random(2, q-1)` <br>
`h = g^s` <br>
`ĥ = (sk.ĝ)^s` <br>
`c = H1(g, sk.vk[sk.id], h, ĉ, di, ĥ)` <br>
`z = s + sk.xi*c` <br>
`return coin_share(sk.id, di, c, z)`<br><br>

**`verify_coin_share(sh: coin_share, coin_name: string, pk: public_key)`**<br>
`ĉ = H(coin_name)`<br>
`h = g^sh.z / pk.vk[sh.id]^sh.c`<br>
`ĥ = pk.ĝ^sh.z / sh.di^sh.c`<br>
`return c == H1(g, pk.vk[sh.id], h, ĉ, sh.di, ĥ)`<br><br>

**`combine_coin_shares(shares: [coin_share])`**<br>
`if k > shares.size then`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`return null`<br>
`ĉ' = 1`<br>
`for each share s in shares do`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`ui = s.di^lag_coeff(s.id)`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`ĉ' = ĉ' * ui`<br>
`return H2(ĉ')`<br><br><br>

# Threshold Encryption (Shoup's method)
[Reference](https://www.shoup.net/papers/thresh1.pdf)<br>

**Needed hash functions:**<br>
```H1(m0, m1, g0, g1, g2, g3)```: Hashes two bit strings and four group elements to an element in [0, q-1]<br>
```H2(g0, g1, g2)```: Hashes three group elements to a single group element<br>
<br>

**Scheme:**

**`encrypt(m: bytes, pk: public_key, L:bytes)`**<br>
`k = gen_symm_key()`<br>
`c = symm_enc(m, k)`<br>
`r = random(2, q-1)` <br>
`z = pk.y^r` <br>
`c_k = k xor z` <br>
`s = random(2, q-1)` <br>
`u = g^r` <br>
`w = g^s` <br>
`û = pk.ĝ^r` <br>
`ŵ = pk.ĝ^s` <br>
`e = H1(c_k, L, u, w, û, ŵ)` <br>
`f = s + re` <br>
`return ciphertext(c_k, L, u, û, e, f, c)`<br><br>

**`verify_ciphertext(ct: ciphertext, pk: public_key)`**<br>
`w = g^ct.f / ct.u^ct.e`<br>
`ŵ = pk.ĝ^ct.f / ct.û^ct.e`<br>
`return ct.e == H1(ct.c_k, ct.L, ct.u, w, ct.û, ŵ)`<br>

**`create_decryption_share(ct: ciphertext, sk: private_key)`**<br>
`ui = ct.u^sk.xi`<br>
`si = random(2, q-1)` <br>
`ûi = ct.u^si` <br>
`ĥi = g^si` <br>
`ei = H2(ui, ûi, ĥi)` <br>
`fi = si + sk.xi*ei` <br>
`return decryption_share(sk.id, ui, ei, fi)`<br><br>

**`verify_decryption_share(sh: decryption_share, ct: ciphertext, pk: public_key)`**<br>
`ûi = ct.u^sh.fi / sh.ui^sh.ei`<br>
`ĥi = g^sh.fi / pk.vk[sh.id]^sh.ei`<br>
`return ct.e == H2(sh.ui, ûi, ĥi)`<br><br>

**`combine_shares(ct: ciphertext, shares: [decryption_share]])`**<br>
`if k > shares.size then`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`return null`<br>
`z = 1`<br>
`for each share s in shares do`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`di = s.ui^lag_coeff(s.id)`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`z = z*di`<br>
`k = ct.c_k xor z`<br>
`m = symm_dec(ct.c, k)`<br>
`return m`<br><br>

# Threshold Encryption (Gap Diffie-Hellman Group)
[Reference](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.119.1717&rep=rep1&type=pdf)<br>

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

**Scheme**


**`encrypt(message: bytes, pk: public_key, L:string)`**<br>
`k = gen_symm_key()`<br>
`c = symm_enc(message, k)`<br>
`r = random(2, q-1)`<br>
`u = g^r`<br>
`c_k = G(public_key.y^r) xor k`<br>
`û = H(u, c)^r`<br>
`return ciphertext(c_k, L, u, û, 0, 0, c)`<br><br>

**`verify_ciphertext(ct: ciphertext)`**<br>
`h = H(ct.u, ct.c)`<br>
`return ê(g, ct.w) == ê(ct.u, h)`<br><br>

**`create_decryption_share(ct: ciphertext, sk: private_key)`**<br>
`if verify_ciphertext(ct) == false then`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`return null`<br>
`ui = ct.u^xi`<br>
`return decryption_share(sk.id, ui, 0, 0)`<br><br>

**`verify_decryption_share(ct: ciphertext, sh: decryption_share, pk: public_key)`**<br>
`return ê(g, sh.ui) == ê(ct.u, pk.vk[sh.id])`<br><br>

**`combine_shares(ct: ciphertext, shares: [decryption_share]])`**<br>
`if k > shares.size then`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`return null`<br>
`z = 1`<br>
`for each share sh in shares do`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`di = sh.ui^lag_coeff(sh.id)`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`z = z*di`<br>
`k = ct.c_k xor G(z)`<br>
`m = symm_dec(ct.c, k)`<br>
`return m`<br><br>

# Threshold Signatures 
[Reference](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/papers/short_signatures_weil_pairing-joc04.pdf)<br>

Again, a GDH group is needed for the following scheme.

**Needed helper methods:**<br>
```ê(g0, g1)```: Determines whether a given tuple (g, g^a, g^b, g^c) is a DH tuple by checking whether ê(g, g^c) = ê(g^a, g^b)<br>
```H(m)```: Hashes a bit string to a single group element<br>
<br>

**Scheme**

**`create_partial_signature(message: bytes, sk: private_key)`**<br>
`ui = H(message)^sk.xi`<br>
`return partial_signature(sk.id, ui, message)`<br><br>

**`verify_partial_signature(psig: partial_signature, pk: public_key, message: bytes)`**<br>
`return ê(g, pk.vk[si.id]) == ê(H(psig.m), psig.ui)`<br><br>

**`combine_partial_signatures(psignatures: [partial_signature], message: bytes)`**<br>
`if k > psignatures.size then`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`return null`<br>
`sig = 1`<br>
`for each partial signature psig in psignatures do`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`di = psig.ui^lag_coeff(psig.id)`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`sig = sig*di`<br>
`return signed_message(sig, message)`<br><br>

**`verify_signature(sig: signed_message)`**<br>
`return ê(g, pk.y) == ê(H(message), sig.sig)`<br><br>
