# Serialisation
*taken from [ieee_std_1363-2000](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/standards/ieee_std_1363-2000.pdf)*<br>

## I2BSP / BS2IP 

Integer shall be written in its unique l-digit representation base 2 

$`x = x_{l-1}2^{l-1} + x_{l-2}2^{l-2} + ... + x_l2 + x_0`$

Where $x_i$ is either $0$ or $1$. Then let the bit $b_i$ have the value xl-i for $1 <= i <= l$. The bit string shall be $b_1b_2...b_l$ 

## BS2OSP / OS2BSP 

To represent a bit string as an octet string, one simply pads enough zeroes on the left to make the number of bits a multiple of eight, and then breaks it up into octets. More precisely, a bit string 

## Elliptic Curve representation 

Compressed form: $`(x_p, ŷ_p), x_p`$ = x-coordinate, $`ŷ_p`$ a bit that's computed as follows: <br>

1. if the field size $`q`$ is an odd prime, then $`ŷ_p = y_p mod 2`$ ($`y_p`$ = rightmost bit of $`y_p`$) 

1. if field size $`q`$ is a power of 2 and $`x_p = 0`$, then $ŷ_p = 0`$ 

1. if the field size $`q`$ is a power of 2 and $`x_p \neq 0`$, then $`ŷ_p`$ is the rightmost bit of the field element $`y_px_p^{-1}`$ 

## EC2OSP / OS2ECP 
Elliptic Curve points as octet strings: PO = PC || X || Y with PC being a single octet of the form `00000UCŶ`, where <br>

- U is 1 if the format is uncompressed or hybrid, 0 otherwise 

- C is 1 if the format is compressed or hybrid, 0 otherwise  

- Ŷ is equal to the bit $`ŷ_p`$ if the format is compressed or hybrid, 0 otherwise 

- X is the octet string of length ceil(log256(q)) representing $`x_p`$ according to FE2OSP <br> 

- Y is the octet string of length ceil(log256(q)) representing $`y_p`$ of P according to FE2OSP if the format is uncompressed or hybrid; Y is an empty string if the format is compressed 

# DL/ECIES
*taken from [ieee_std_1363a-2004](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/standards/ieee_std_1363a-2004.pdf*<br>

Ciphertext: (V, C, T) where V is the sender's public key, C is the encrypted message and T = MAC_K2(C || P2 || L2)
P2 are encoding parameters and L2 is either an empty string or the length of P2 in bits (when in DHAES mode).

**NOTE:** Encoding of domain parameters not specified

## Scheme options
The following options shall be established or otherwise agreed upon between the parties to the scheme (the sender and the recipient):

1. The secret value derivation primitive, which shall be DLSVDP-DH, DLSVDP-DHC, ECSVDP-DH, or ECSVDP-DH

2. For the -DHC secret value derivation primitive, and indication as to whether or not compatibility with the corresponding -DH primitive is desired

3. The method for encrypting the message, which shall be either:<br>

    - A stream cipher based on a key derivation function, where the key derivation function should be KDF2 or a function designated for use with DL/ECIES in an amendment to this standard (this method is only recommended for relatively short messages such as symmetric keys, and in non-DHAES mode, the messages should have a fixed length for a given public key)

    - A key derivation function combined with a symmetric encryption scheme, where the key derivation function should be KDF2 or a technique designated for use with DL/ECIES in an amendment to this standard.

4. The message authentication code, which should be MAC1, or a MAC designated for use with DL/ECIES in an amendment to this standard

5. And indication as to whether to operate in "DHAES" mode, i.e., whether to include a representation of the sender's public key as an input to the key derivation function

6. In the EC case, a pair of primitives for converting elliptic curve points to and from octet strings appropriate for the underlying finite field.




# BLS
*Taken from [draft-irtf-cfrg-bls-signature-04.](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/standards/draft-irtf-cfrg-bls-signature-04.txt)* <br>

The signature and public key are created using the following methods: <br>

For minimal-signature-size:<br>
point_to_pubkey(P) := point_to_octets_E2(P) <br>
point_to_signature(P) := point_to_octets_E1(P)

For minimal-pubkey-size:<br>
point_to_pubkey(P) := point_to_octets_E1(P) <br>
point_to_signature(P) := point_to_octets_E2(P) <br><br>

The signature is prepended with an **ID** identifying a **ciphersuite format** presented in the following section.


## Ciphersuite format
   A ciphersuite specifies the following parameters:

*  SC: the scheme, one of basic, message-augmentation, or proof-of-possession.

*  SV: the signature variant, either minimal-signature-size or minimal-pubkey-size.

*  EC: a pairing-friendly elliptic curve, plus all associated functionality

*  H: a cryptographic hash function.

*  hash_to_point: a hash from arbitrary strings to elliptic curve <br>
    points. hash_to_point MUST be defined in terms of a hash-to-curve <br>
    suite (found in [I-D.irtf-cfrg-hash-to-curve](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-10)).

    The RECOMMENDED hash-to-curve domain separation tag is the
    ciphersuite ID string defined below.

*  hash_pubkey_to_point (only specified when SC is proof-of-possession): <br> 
    a hash from serialized public keys to elliptic curve <br>
    points. hash_pubkey_to_point MUST be defined in terms of a hash-to-curve <br> suite (found in [I-D.irtf-cfrg-hash-to-curve](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-10)).

The above parameters are specified in the ciphersuite ID, an ASCII string. <br> 
The required format for this string is ``"BLS_SIG_" || H2C_SUITE_ID || SC_TAG || "_"``, <br> where strings in double quotes are ASCII-encoded literals.

-  H2C_SUITE_ID is the suite ID of the hash-to-curve suite used to <br>
define the hash_to_point and hash_pubkey_to_point functions.

-  SC_TAG is a string indicating the scheme and, optionally, <br>
additional information.  The first three characters of this <br>
string MUST chosen as follows:

    - "NUL" if SC is basic,

    -  "AUG" if SC is message-augmentation, or

    -  "POP" if SC is proof-of-possession.
    
    -  Other values MUST NOT be used.

SC_TAG MAY be used to encode other information about the <br>
ciphersuite, for example, a version number.  When used in this <br>
way, SC_TAG MUST contain only ASCII characters between 0x21 and <br>
0x7e (inclusive), except that it MUST NOT contain underscore 
(0x5f).

The RECOMMENDED way to add user-defined information to SC_TAG <br>
is to append a colon (':', ASCII 0x3a) and then the <br>
informational string.  For example, "NUL:version=2" is an <br>
appropriate SC_TAG value.

Below we show three ciphersuites built on the BLS12-381 elliptic curve.

**1.  Basic**

*BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_* is defined as follows:

   *  SC: basic

   *  SV: minimal-signature-size

   *  EC: BLS12-381, as defined in Appendix A.

   *  H: SHA-256

   *  hash_to_point: BLS12381G1_XMD:SHA-256_SSWU_RO_ with the ASCII-
      encoded domain separation tag

      *BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_*

   *BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_* is identical to <br>
   *BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_*, except for the following
   parameters:

   *  SV: minimal-pubkey-size

   *  hash_to_point: *BLS12381G2_XMD:SHA-256_SSWU_RO_* with the ASCII-
      encoded domain separation tag

      *BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_*

    
**2.  Message augmentation**

   *BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_* is defined as follows:

   *  SC: message-augmentation

   *  SV: minimal-signature-size

   *  EC: BLS12-381, as defined in Appendix A.

   *  H: SHA-256

   *  hash_to_point: *BLS12381G1_XMD:SHA-256_SSWU_RO_* with the ASCII-
      encoded domain separation tag

      *BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_*

   *BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_* is identical to <br>
   *BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_*, except for the following
   parameters:

   *  SV: minimal-pubkey-size

   *  hash_to_point: *BLS12381G2_XMD:SHA-256_SSWU_RO_* with the ASCII-
      encoded domain separation tag

      *BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_*

**3.  Proof of possession**

   *BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_* is defined as follows:

   *  SC: proof-of-possession

   *  SV: minimal-signature-size

   *  EC: BLS12-381, as defined in Appendix A.

   *  H: SHA-256

   *  hash_to_point: *BLS12381G1_XMD:SHA-256_SSWU_RO_* with the ASCII-
      encoded domain separation tag

      *BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_*

   *  hash_pubkey_to_point: *BLS12381G1_XMD:SHA-256_SSWU_RO_* with the <br>
      ASCII-encoded domain separation tag

      *BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_*

*BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_* is identical to <br>
   *BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_*, except for the following <br>
   parameters:

   *  SV: minimal-pubkey-size

   *  hash_to_point: *BLS12381G2_XMD:SHA-256_SSWU_RO_* with the <br> ASCII-
      encoded domain separation tag

      *BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_*

   *  hash_pubkey_to_point: *BLS12381G2_XMD:SHA-256_SSWU_RO_* with the <br>
      ASCII-encoded domain separation tag <br>
      *BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_*

