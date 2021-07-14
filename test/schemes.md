# Threshold Schemes Summary

Operating on a cyclic group *G* of order *q* with generator *g*


**public_key**
- y:&nbsp;&nbsp;&nbsp;public key value
- vk:   verification key consisting of n values vk[i] = g^xi
- ĝ:&nbsp;&nbsp;&nbsp;alternate generator

**private_key** 
- id: key identifier
- xᵢ: private key share
- y:&nbsp;&nbsp;public key value
- vk: verification key consisting of n values vk[i] = g^xi
- ĝ:&nbsp;&nbsp;alternate generator

**decryption_share**
- id: share identifier
- dᵢ: decryption share

**coin_share**
- id: share identifier
- dᵢ: coin share
- c:  zkp parameter
- z:  zkp parameter
<br>

# Key Generation

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

**`verify_coin_share(share: coin_share, coin_name: string, pk: public_key)`**<br>
`ĉ = H(coin_name)`<br>
`h = g^share.z / pk.vk[share.id]^share.c`<br>
`ĥ = pk.ĝ^share.z / share.di^share.c`<br>
`return c == H1(g, pk.vk[share.id], h, ĉ, share.di, ĥ)`<br><br>

**`combine_coin_shares(shares: [coin_share])`**<br>
`ĉ' = 1`<br>
`for each share s in shares do`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`ui = s.di^lag_coeff(s.id)`<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`ĉ' = ĉ' * ui`<br>
`return H2(ĉ')`<br>
