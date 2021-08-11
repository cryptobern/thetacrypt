# BLS
*Taken from [draft-irtf-cfrg-bls-signature-04.](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/standards/draft-irtf-cfrg-bls-signature-04.txt)* <br>

A pairing-friendly elliptic curve defines the following primitives: <br>

-  E1, E2: elliptic curve groups defined over finite fields.  It is assumed that E1 has a more compact representation than
   E2, i.e., because E1 is defined over a smaller field than E2.

-  G1, G2: subgroups of E1 and E2 (respectively) having prime
   order r.

-  P1, P2: distinguished points that generate G1 and G2,
   respectively.

-  GT: a subgroup, of prime order r, of the multiplicative group
   of a field extension.

-  e : G1 x G2 -> GT: a non-degenerate bilinear map.

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

