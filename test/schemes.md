# Threshold Schemes

## Key primitives
Operating on a cyclic group $G$ of order $q$ with generator $g$


**public_key**
- $y$: public key value
- $h$: verification key 
- $\bar{g}$: alternate generator

**private_key** 
- $x_i$: private key share
- $y$: public key
<br><br>

KeyGen(k, n)
--------------
$x \in [2, q-1]]\\$ 
$y = g^x\\$
${x_1, .. x_n} = share\_secret(x, k, n)\\$
$h = \{g^{x_1},...,g^{x_n}\}$
<br><br>

