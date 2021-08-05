# PKCS #1

## About PKCS

   The Public-Key Cryptography Standards are specifications produced by
   RSA Laboratories in cooperation with secure systems developers
   worldwide for the purpose of accelerating the deployment of public-
   key cryptography.  First published in 1991 as a result of meetings
   with a small group of early adopters of public-key technology, the
   PKCS documents have become widely referenced and implemented.
   Contributions from the PKCS series have become part of many formal
   and de facto standards, including ANSI X9 and IEEE P1363 documents,
   PKIX, Secure Electronic Transaction (SET), S/MIME, SSL/TLS, and
   Wireless Application Protocol (WAP) / WAP Transport Layer Security
   (WTLS).

   Further development of most PKCS documents occurs through the IETF.
   Suggestions for improvement are welcome.
<br>

[Link to PKCS #1](https://datatracker.ietf.org/doc/html/rfc3447)


## RSA Key Representation

This section defines ASN.1 object identifiers for RSA public and
private keys and defines the types `RSAPublicKey` and `RSAPrivateKey`.
The intended application of these definitions includes X.509
certificates, PKCS #8, and PKCS #12.

The object identifier `rsaEncryption` identifies RSA public and private
keys as defined below  The parameters field
has associated with this OID in a value of type AlgorithmIdentifier
SHALL have a value of type NULL.

      rsaEncryption    OBJECT IDENTIFIER ::= { pkcs-1 1 }

The definitions in this section have been extended to support multi-
prime RSA, but they are backward compatible with previous versions.

## RSA Public Key Syntax

An RSA public key should be represented with the ASN.1 type
`RSAPublicKey`:

        RSAPublicKey ::= SEQUENCE {
            modulus           INTEGER,  -- n
            publicExponent    INTEGER   -- e
        }

The fields of type `RSAPublicKey` have the following meanings:

- `modulus` is the RSA modulus $`n`$.

- `publicExponent` is the RSA public exponent $`e`$.



## RSA Private Key Syntax

   An RSA private key should be represented with the ASN.1 type
   `RSAPrivateKey`:

         RSAPrivateKey ::= SEQUENCE {
             version           Version,
             modulus           INTEGER,  -- n
             publicExponent    INTEGER,  -- e
             privateExponent   INTEGER,  -- d
             prime1            INTEGER,  -- p
             prime2            INTEGER,  -- q
             exponent1         INTEGER,  -- d mod (p-1)
             exponent2         INTEGER,  -- d mod (q-1)
             coefficient       INTEGER,  -- (inverse of q) mod p
             otherPrimeInfos   OtherPrimeInfos OPTIONAL
         }

The fields of type `RSAPrivateKey` have the following meanings:

- `version` is the version number, for compatibility with future
    revisions of this document.  It SHALL be 0 for this version of the
    document, unless multi-prime is used; in which case, it SHALL be
    1.

        Version ::= INTEGER { two-prime(0), multi(1) }
            (CONSTRAINED BY
            {-- version must be multi if otherPrimeInfos present --})

-  `modulus` is the RSA modulus $`n`$.

-  `publicExponent` is the RSA public exponent $`e`$.

-  `privateExponent` is the RSA private exponent $`d`$.

-  `prime1` is the prime factor $`p`$ of $`n`$.

-  `prime2` is the prime factor $`q`$ of $`n`$.

-  `exponent1` is $`d \mod (p - 1)`$.

-  `exponent2` is $`d \mod (q - 1)`$.

-  `coefficient` is the CRT coefficient $`q^{-1} \mod p`$.

-  `otherPrimeInfos` contains the information for the additional primes
    $`r_3, ..., r_u`$, in order.  It SHALL be omitted if version is 0 and
    SHALL contain at least one instance of OtherPrimeInfo if version
    is 1.

        OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo

        OtherPrimeInfo ::= SEQUENCE {
            prime             INTEGER,  -- ri
            exponent          INTEGER,  -- di
            coefficient       INTEGER   -- ti
        }

The fields of type `OtherPrimeInfo` have the following meanings:

-  `prime` is a prime factor $`r_i`$ of $`n`$, where $`i >= 3`$.

-  `exponent` is $`d_i = d \mod (r_i - 1)`$.

-  `coefficient` is the CRT coefficient $`t_i = (r_1 * r_2 * ... *
    r_(i-1))^{-1} \mod r_i`$.

Note: It is important to protect the RSA private key against both
disclosure and modification.  Techniques for such protection are
outside the scope of this document.  Methods for storing and
distributing private keys and other cryptographic data are described
in PKCS #12 and #15. <br><br>


## PKCS#1 v1.5 Signature Encoding (RSASSA-PKCS-v1_5)

RSASSA-PKCS-v1_5 is deterministic, has no known security weaknesses and has been widely used since the 1990s. ([source](https://www.cryptosys.net/pki/manpki/pki_rsaschemes.html)) <br>

An RSA signature is a sequence of bytes of the same size of the modulus. If the key uses a 1024-bit modulus n, then the signature value is, numerically, an integer in the $`1..n−1`$ range, and the PKCS#1 standard specifies that this integer should be encoded as a sequence of bytes of the same length as would be needed to encode the modulus, i.e. 128 bytes for a 1024-bit modulus (big-endian unsigned convention).

The signature process looks like this:

- The message to be signed $`m`$ is hashed with hash value $`h`$, yielding $`h(m)`$, which is a sequence of bytes (say, 32 bytes if $`h`$
is SHA-256).
The hash value is *padded*: a byte sequence is assembled, consisting of, in that order: a byte of value 0x00, a byte of value 0x01, some bytes of value 0xFF, a byte of value 0x00, a fixed header sequence H, and then $`h(m)`$. The header sequence $`H`$ identifies the hash function (strictly speaking, there are for each hash function two possible header values, and I have encountered both). The number of 0xFF bytes is adjusted so that the total sequence length is exactly equal to the encoding length of the modulus (i.e. 128 bytes for a 1024-bit modulus).

- The padded value is then interpreted as an integer $`x`$, by decoding it with the big-endian convention. Due to the sequence size and the fact that the sequence begins with a 0x00, the value $`x`$ is necessarily in the $`1..n−1`$ range.

- The value $`x`$ is raised to the power d (private exponent) modulo n, yielding $`s = x^d(\mod n)`$

- The s value is encoded into a sequence of the same length as n; that's the signature.

To verify, the signature is decoded back into the integer $`s`$, then $`x`$ is recovered with $`x=s^e(\mod n)`$, and encoded back. The verifier then checks that the padding as explained above has the proper format, and that it ends with $`h(m)`$ for the message $`m`$.
<br>
[source](https://crypto.stackexchange.com/questions/10824/what-does-an-rsa-signature-look-like)

## RSASSA-PKCS-v1_5 vs RSASSA-PSS 
PKCS#1 v1.5 padding has the following drawbacks.

1. It is deterministic, which is not a requirement for signatures and this can actually be detrimental to security in some very specific situations.

1. It's missing a security proof; PSS has a security proof (for the padding mode, not for RSA itself of course). That said, PKCS#1 v1.5 padding for signature generation has not been broken (unlike PKCS#1 v1.5 padding for encryption, which does have vulnerabilities).

PSS has drawbacks as well:

1. it is more complex to implement;

1. it is definitely not as prevalent as PKCS#1 v1.5 padding - probably because PKCS#1 v1.5 padding is older and hasn't been broken;

1. it requires configuration (both during signature generation and verification).


## PKCS #1 RSASSA-PSS Signature Scheme
   The length of messages on which RSASSA-PSS can operate is either
   unrestricted or constrained by a very large number, depending on the
   hash function underlying the EMSA-PSS encoding method.

   Assuming that computing e-th roots modulo n is infeasible and the
   hash and mask generation functions in EMSA-PSS have appropriate
   properties, RSASSA-PSS provides secure signatures.  This assurance is
   provable in the sense that the difficulty of forging signatures can
   be directly related to the difficulty of inverting the RSA function,
   provided that the hash and mask generation functions are viewed as
   black boxes or random oracles.  The bounds in the security proof are
   essentially "tight", meaning that the success probability and running
   time for the best forger against RSASSA-PSS are very close to the
   corresponding parameters for the best RSA inversion algorithm; 

   In contrast to the RSASSA-PKCS1-v1_5 signature scheme, a hash
   function identifier is not embedded in the EMSA-PSS encoded message,
   so in theory it is possible for an adversary to substitute a
   different (and potentially weaker) hash function than the one
   selected by the signer.  Therefore, it is recommended that the EMSA-
   PSS mask generation function be based on the same hash function.  In
   this manner the entire encoded message will be dependent on the hash
   function and it will be difficult for an opponent to substitute a
   different hash function than the one intended by the signer.  This
   matching of hash functions is only for the purpose of preventing hash
   function substitution, and is not necessary if hash function
   substitution is addressed by other means (e.g., the verifier accepts
   only a designated hash function). The provable security of RSASSA-PSS does not rely on
   the hash function in the mask generation function being the same as
   the hash function applied to the message.

   RSASSA-PSS is different from other RSA-based signature schemes in
   that it is probabilistic rather than deterministic, incorporating a
   randomly generated salt value.  The salt value enhances the security of the scheme by affording a "tighter" security proof than
   deterministic alternatives such as Full Domain Hashing (FDH); However, the randomness is not critical to security.
   In situations where random generation is not possible, a fixed value
   or a sequence number could be employed instead, with the resulting
   provable security similar to that of FDH.



### **OS2IP**

   OS2IP converts an octet string to a nonnegative integer.

    OS2IP (X)

    Input:
    X        octet string to be converted

    Output:
    x        corresponding nonnegative integer

   Steps:

   1. Let $`X_1 X_2 ... X_{xLen}`$ be the octets of X from first to last,
      and let $`x_{xLen-i}`$ be the integer value of the octet $`X_i`$ for
      $`1 <= i <= xLen`$.

   2. Let $`x = x_(xLen-1) 256^(xLen-1) + x_(xLen-2) 256^(xLen-2) + ...
      + x_1 256 + x_0`$.

   3. Output $`x`$.

### **I2OSP**

   I2OSP converts a nonnegative integer to an octet string of a
   specified length.

    I2OSP (x, xLen)

    Input:
    x        nonnegative integer to be converted
    xLen     intended length of the resulting octet string

    Output:
    X        corresponding octet string of length xLen

    Error: "integer too large"

   Steps:

   1. If x >= 256^xLen, output "integer too large" and stop.

   2. Write the integer x in its unique xLen-digit representation in
      base 256:

         $`x = x_{xLen-1} 256^{xLen-1} + x_{xLen-2} 256^{xLen-2} + ... + x_1 256 + x_0`$,

      where $`0 <= x_i < 256`$ (note that one or more leading digits will be
      zero if $`x`$ is less than $`256^{xLen-1}`$).

   3. Let the octet X_i have the integer value x_(xLen-i) for 1 <= i <=
      xLen.  Output the octet string

         $`X = X_1 X_2 ... X_{xLen}`$.

### **Signature generation operation**

    RSASSA-PSS-SIGN (K, M)

    Input:
    K        signer's RSA private key
    M        message to be signed, an octet string

    Output:
    S        signature, an octet string of length k, where k is the
                length in octets of the RSA modulus n

    Errors: "message too long;" "encoding error"

   Steps:

   1. EMSA-PSS encoding: Apply the EMSA-PSS encoding operation (Section
      9.1.1) to the message M to produce an encoded message EM of length
      \ceil ((modBits - 1)/8) octets such that the bit length of the
      integer OS2IP (EM) (see Section 4.2) is at most modBits - 1, where
      modBits is the length in bits of the RSA modulus n:

            EM = EMSA-PSS-ENCODE (M, modBits - 1).

      Note that the octet length of EM will be one less than k if
      modBits - 1 is divisible by 8 and equal to k otherwise.  If the
      encoding operation outputs "message too long," output "message too
      long" and stop.  If the encoding operation outputs "encoding
      error," output "encoding error" and stop.

   2. RSA signature:

      - Convert the encoded message EM to an integer message
         representative m:

            m = OS2IP (EM).


      - Apply the RSASP1 signature primitive (Section 5.2.1) to the RSA
         private key K and the message representative m to produce an
         integer signature representative s:

            s = RSASP1 (K, m).

      - Convert the signature representative s to a signature S of
         length k octets (see Section 4.1):

            S = I2OSP (s, k).

   3. Output the signature S.

### **Signature verification operation**
    RSASSA-PSS-VERIFY ((n, e), M, S)

    Input:
    (n, e)   signer's RSA public key
    M        message whose signature is to be verified, an octet string
    S        signature to be verified, an octet string of length k, where
                k is the length in octets of the RSA modulus n

    Output:
    "valid signature" or "invalid signature"

   Steps:

   1. Length checking: If the length of the signature S is not k octets,
      output "invalid signature" and stop.

   2. RSA verification:

      a. Convert the signature S to an integer signature representative
         s (see Section 4.2):

             s = OS2IP (S).

      b. Apply the RSAVP1 verification primitive (Section 5.2.2) to the
         RSA public key (n, e) and the signature representative s to
         produce an integer message representative m:

                m = RSAVP1 ((n, e), s).

         If RSAVP1 output "signature representative out of range,"
         output "invalid signature" and stop.


      c. Convert the message representative m to an encoded message EM
         of length emLen = \ceil ((modBits - 1)/8) octets, where modBits
         is the length in bits of the RSA modulus n (see Section 4.1):

                EM = I2OSP (m, emLen).

         Note that emLen will be one less than k if modBits - 1 is
         divisible by 8 and equal to k otherwise.  If I2OSP outputs
         "integer too large," output "invalid signature" and stop.

   3. EMSA-PSS verification: Apply the EMSA-PSS verification operation
      (Section 9.1.2) to the message M and the encoded message EM to
      determine whether they are consistent:

            Result = EMSA-PSS-VERIFY (M, EM, modBits - 1).

   4. If Result = "consistent," output "valid signature." Otherwise,
      output "invalid signature."

## Scheme Identification
This section defines object identifiers for the encryption and
signature schemes.  The schemes compatible with PKCS #1 v1.5 have the
same definitions as in PKCS #1 v1.5.  The intended application of
these definitions includes X.509 certificates and PKCS #7.

Here are type identifier definitions for the PKCS #1 OIDs:

    PKCS1Algorithms    ALGORITHM-IDENTIFIER ::= {
        { OID rsaEncryption                PARAMETERS NULL } |
        { OID md2WithRSAEncryption         PARAMETERS NULL } |
        { OID md5WithRSAEncryption         PARAMETERS NULL } |
        { OID sha1WithRSAEncryption        PARAMETERS NULL } |
        { OID sha224WithRSAEncryption      PARAMETERS NULL } |
        { OID sha256WithRSAEncryption      PARAMETERS NULL } |
        { OID sha384WithRSAEncryption      PARAMETERS NULL } |
        { OID sha512WithRSAEncryption      PARAMETERS NULL } |
        { OID sha512-224WithRSAEncryption  PARAMETERS NULL } |
        { OID sha512-256WithRSAEncryption  PARAMETERS NULL } |
        { OID id-RSAES-OAEP   PARAMETERS RSAES-OAEP-params } |
        PKCS1PSourceAlgorithms                               |
        { OID id-RSASSA-PSS   PARAMETERS RSASSA-PSS-params },
        ...  -- Allows for future expansion --
    }

## RSAES-OAEP

   The object identifier `id-RSAES-OAEP` identifies the RSAES-OAEP
   encryption scheme.

       id-RSAES-OAEP    OBJECT IDENTIFIER ::= { pkcs-1 7 }

   The parameters field associated with this OID in a value of type
   AlgorithmIdentifier SHALL have a value of type RSAES-OAEP-params:

    RSAES-OAEP-params ::= SEQUENCE {
        hashAlgorithm      [0] HashAlgorithm     DEFAULT sha1,
        maskGenAlgorithm   [1] MaskGenAlgorithm  DEFAULT mgf1SHA1,
        pSourceAlgorithm   [2] PSourceAlgorithm  DEFAULT pSpecifiedEmpty
    }

   The fields of type `RSAES-OAEP-params` have the following meanings:

-  `hashAlgorithm` identifies the hash function.  It SHALL be an
      algorithm ID with an OID in the set OAEP-PSSDigestAlgorithms.  For
      a discussion of supported hash functions, see Appendix B.1.


       HashAlgorithm ::= AlgorithmIdentifier {
          {OAEP-PSSDigestAlgorithms}
       }

       OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
           { OID id-sha1       PARAMETERS NULL }|
           { OID id-sha224     PARAMETERS NULL }|
           { OID id-sha256     PARAMETERS NULL }|
           { OID id-sha384     PARAMETERS NULL }|
           { OID id-sha512     PARAMETERS NULL }|
           { OID id-sha512-224 PARAMETERS NULL }|
           { OID id-sha512-256 PARAMETERS NULL },
           ...  -- Allows for future expansion --
       }

   The default hash function is SHA-1:

       sha1    HashAlgorithm ::= {
           algorithm   id-sha1,
           parameters  SHA1Parameters : NULL
       }

       SHA1Parameters ::= NULL

-  `maskGenAlgorithm` identifies the mask generation function.  It
    SHALL be an algorithm ID with an OID in the set
    `PKCS1MGFAlgorithms`, which for this version SHALL consist of
    `id-mgf1`, identifying the MGF1 mask generation function.  The parameters field associated with `id-mgf1`
    SHALL be an algorithm ID with an OID in the set
    `OAEP-PSSDigestAlgorithms`, identifying the hash function on which
    MGF1 is based.

        MaskGenAlgorithm ::= AlgorithmIdentifier { {PKCS1MGFAlgorithms} }

        PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
            { OID id-mgf1 PARAMETERS HashAlgorithm },
            ...  -- Allows for future expansion --
        }

-  The default mask generation function is MGF1 with SHA-1:

        mgf1SHA1    MaskGenAlgorithm ::= {
            algorithm   id-mgf1,
            parameters  HashAlgorithm : sha1
        }


-  `pSourceAlgorithm` identifies the source (and possibly the value) of
      the label L.  It SHALL be an algorithm ID with an OID in the set
      PKCS1PSourceAlgorithms, which for this version SHALL consist of
      id-pSpecified, indicating that the label is specified explicitly.
      The parameters field associated with id-pSpecified SHALL have a
      value of type OCTET STRING, containing the label.  In previous
      versions of this specification, the term "encoding parameters" was
      used rather than "label", hence the name of the type below.

       PSourceAlgorithm ::= AlgorithmIdentifier {
          {PKCS1PSourceAlgorithms}
       }

       PKCS1PSourceAlgorithms    ALGORITHM-IDENTIFIER ::= {
           { OID id-pSpecified PARAMETERS EncodingParameters },
           ...  -- Allows for future expansion --
       }

       id-pSpecified    OBJECT IDENTIFIER ::= { pkcs-1 9 }

       EncodingParameters ::= OCTET STRING(SIZE(0..MAX))

-  The default label is an empty string (so that lHash will contain
      the hash of the empty string):

       pSpecifiedEmpty    PSourceAlgorithm ::= {
           algorithm   id-pSpecified,
           parameters  EncodingParameters : emptyString
       }

       emptyString    EncodingParameters ::= ''H

   If all of the default values of the fields in RSAES-OAEP-params are
   used, then the algorithm identifier will have the following value:

       rSAES-OAEP-Default-Identifier    RSAES-AlgorithmIdentifier ::= {
           algorithm   id-RSAES-OAEP,
           parameters  RSAES-OAEP-params : {
               hashAlgorithm       sha1,
               maskGenAlgorithm    mgf1SHA1,
               pSourceAlgorithm    pSpecifiedEmpty
           }
       }

       RSAES-AlgorithmIdentifier ::= AlgorithmIdentifier  {
           {PKCS1Algorithms}
       }





## RSAES-PKCS-v1_5

   The object identifier rsaEncryption (see Appendix A.1) identifies the
   RSAES-PKCS1-v1_5 encryption scheme.  The parameters field associated
   with this OID in a value of type AlgorithmIdentifier SHALL have a
   value of type NULL.  This is the same as in PKCS #1 v1.5.

       rsaEncryption    OBJECT IDENTIFIER ::= { pkcs-1 1 }

## RSASSA-PSS

   The object identifier id-RSASSA-PSS identifies the RSASSA-PSS
   encryption scheme.

       id-RSASSA-PSS    OBJECT IDENTIFIER ::= { pkcs-1 10 }

   The parameters field associated with this OID in a value of type
   AlgorithmIdentifier SHALL have a value of type RSASSA-PSS-params:

    RSASSA-PSS-params ::= SEQUENCE {
        hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
        maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
        saltLength         [2] INTEGER            DEFAULT 20,
        trailerField       [3] TrailerField       DEFAULT trailerFieldBC
    }

   The fields of type RSASSA-PSS-params have the following meanings:

   -  `hashAlgorithm` identifies the hash function.  It SHALL be an
      algorithm ID with an OID in the set `OAEP-PSSDigestAlgorithms`.  The default hash function is SHA-1.

   -  `maskGenAlgorithm` identifies the mask generation function.  It
      SHALL be an algorithm ID with an OID in the set PKCS1MGFAlgorithms
      (see Appendix A.2.1).  The default mask generation function is
      MGF1 with SHA-1.  For MGF1 (and more generally, for other mask
      generation functions based on a hash function), it is RECOMMENDED
      that the underlying hash function be the same as the one
      identified by hashAlgorithm; 

   - `saltLength` is the octet length of the salt.  It SHALL be an
      integer.  For a given hashAlgorithm, the default value of
      saltLength is the octet length of the hash value.  Unlike the
      other fields of type `RSASSA-PSS-params`, `saltLength` does not need
      to be fixed for a given RSA key pair.

   -  `trailerField` is the trailer field number, for compatibility with
      IEEE 1363a [IEEE1363A].  It SHALL be 1 for this version of the
      document, which represents the trailer field with hexadecimal
      value 0xbc.  Other trailer fields (including the trailer field
      HashID || 0xcc in IEEE 1363a) are not supported in this document.

       TrailerField ::= INTEGER { trailerFieldBC(1) }

   If the default values of the hashAlgorithm, maskGenAlgorithm, and
   trailerField fields of RSASSA-PSS-params are used, then the algorithm
   identifier will have the following value:

       rSASSA-PSS-Default-Identifier    RSASSA-AlgorithmIdentifier ::= {
           algorithm   id-RSASSA-PSS,
           parameters  RSASSA-PSS-params : {
               hashAlgorithm       sha1,
               maskGenAlgorithm    mgf1SHA1,
               saltLength          20,
               trailerField        trailerFieldBC
           }
       }

       RSASSA-AlgorithmIdentifier ::= AlgorithmIdentifier {
           {PKCS1Algorithms}
       }

   Note: In some applications, the hash function underlying a signature
   scheme is identified separately from the rest of the operations in
   the signature scheme.  For instance, in PKCS #7 [RFC2315], a hash
   function identifier is placed before the message and a "digest
   encryption" algorithm identifier (indicating the rest of the
   operations) is carried with the signature.  In order for PKCS #7 to
   support the RSASSA-PSS signature scheme, an object identifier would
   need to be defined for the operations in RSASSA-PSS after the hash
   function (analogous to the RSAEncryption OID for the
   RSASSA-PKCS1-v1_5 scheme).  S/MIME Cryptographic Message Syntax (CMS)
   [RFC5652] takes a different approach.  Although a hash function
   identifier is placed before the message, an algorithm identifier for
   the full signature scheme may be carried with a CMS signature (this
   is done for DSA signatures).  Following this convention, the
   id-RSASSA-PSS OID can be used to identify RSASSA-PSS signatures in
   CMS.  Since CMS is considered the successor to PKCS #7 and new
   developments such as the addition of support for RSASSA-PSS will be
   pursued with respect to CMS rather than PKCS #7, an OID for the "rest
   of" RSASSA-PSS is not defined in this version of PKCS #1.

##  RSASSA-PKCS-v1_5

   The object identifier for RSASSA-PKCS1-v1_5 SHALL be one of the
   following.  The choice of OID depends on the choice of hash
   algorithm: MD2, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
   SHA-512/224, or SHA-512/256.  Note that if either MD2 or MD5 is used,
   then the OID is just as in PKCS #1 v1.5.  For each OID, the
   parameters field associated with this OID in a value of type
   AlgorithmIdentifier SHALL have a value of type NULL.  The OID should
   be chosen in accordance with the following table:

Hash algorithm  |  OID |
----------------| ------------------------------------------|
MD2  |            md2WithRSAEncryption        ::= {pkcs-1 2}
MD5    |          md5WithRSAEncryption        ::= {pkcs-1 4}
SHA-1    |        sha1WithRSAEncryption       ::= {pkcs-1 5}
SHA-256  |        sha224WithRSAEncryption     ::= {pkcs-1 14}
SHA-256  |        sha256WithRSAEncryption     ::= {pkcs-1 11}
SHA-384   |       sha384WithRSAEncryption     ::= {pkcs-1 12}
SHA-512    |      sha512WithRSAEncryption     ::= {pkcs-1 13}
SHA-512/224 |     sha512-224WithRSAEncryption ::= {pkcs-1 15}
SHA-512/256  |    sha512-256WithRSAEncryption ::= {pkcs-1 16}

   The EMSA-PKCS1-v1_5 encoding method includes an ASN.1 value of type
   DigestInfo, where the type DigestInfo has the syntax

       DigestInfo ::= SEQUENCE {
           digestAlgorithm DigestAlgorithm,
           digest OCTET STRING
       }

   digestAlgorithm identifies the hash function and SHALL be an
   algorithm ID with an OID in the set PKCS1-v1-5DigestAlgorithms.


       DigestAlgorithm ::= AlgorithmIdentifier {
          {PKCS1-v1-5DigestAlgorithms}
       }

       PKCS1-v1-5DigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
           { OID id-md2        PARAMETERS NULL }|
           { OID id-md5        PARAMETERS NULL }|
           { OID id-sha1       PARAMETERS NULL }|
           { OID id-sha224     PARAMETERS NULL }|
           { OID id-sha256     PARAMETERS NULL }|
           { OID id-sha384     PARAMETERS NULL }|
           { OID id-sha512     PARAMETERS NULL }|
           { OID id-sha512-224 PARAMETERS NULL }|
           { OID id-sha512-256 PARAMETERS NULL }
       }

# Supporting Techniques

   This section gives several examples of underlying functions
   supporting the encryption schemes in Section 7 and the encoding
   methods in Section 9.  A range of techniques is given here to allow
   compatibility with existing applications as well as migration to new
   techniques.  While these supporting techniques are appropriate for
   applications to implement, none of them is required to be
   implemented.  It is expected that profiles for PKCS #1 v2.2 will be
   developed that specify particular supporting techniques.

   This section also gives object identifiers for the supporting
   techniques.

##  Hash Functions

   Hash functions are used in the operations contained in Sections 7 and
   9.  Hash functions are deterministic, meaning that the output is
   completely determined by the input.  Hash functions take octet
   strings of variable length and generate fixed-length octet strings.
   The hash functions used in the operations contained in Sections 7 and
   9 should generally be collision-resistant.  This means that it is
   infeasible to find two distinct inputs to the hash function that
   produce the same output.  A collision-resistant hash function also
   has the desirable property of being one-way; this means that given an
   output, it is infeasible to find an input whose hash is the specified
   output.  In addition to the requirements, the hash function should
   yield a mask generation function (Appendix B.2) with pseudorandom
   output.


   Nine hash functions are given as examples for the encoding methods in
   this document: MD2 [RFC1319] (which was retired by [RFC6149]), MD5
   [RFC1321], SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224,
   and SHA-512/256 [SHS].  For the RSAES-OAEP encryption scheme and
   EMSA-PSS encoding method, only SHA-1, SHA-224, SHA-256, SHA-384, SHA-
   512, SHA-512/224, and SHA-512/256 are RECOMMENDED.  For the EMSA-
   PKCS1-v1_5 encoding method, SHA-224, SHA-256, SHA-384, SHA-512, SHA-
   512/224, and SHA-512/256 are RECOMMENDED for new applications.  MD2,
   MD5, and SHA-1 are recommended only for compatibility with existing
   applications based on PKCS #1 v1.5.

   The object identifiers id-md2, id-md5, id-sha1, id-sha224, id-sha256,
   id-sha384, id-sha512, id-sha512/224, and id-sha512/256 identify the
   respective hash functions:

       id-md2      OBJECT IDENTIFIER ::= {
           iso (1) member-body (2) us (840) rsadsi (113549)
           digestAlgorithm (2) 2
       }

       id-md5      OBJECT IDENTIFIER ::= {
           iso (1) member-body (2) us (840) rsadsi (113549)
           digestAlgorithm (2) 5
       }

       id-sha1    OBJECT IDENTIFIER ::= {
           iso(1) identified-organization(3) oiw(14) secsig(3)
            algorithms(2) 26
       }

       id-sha224    OBJECT IDENTIFIER ::= {
           joint-iso-itu-t (2) country (16) us (840) organization (1)
           gov (101) csor (3) nistalgorithm (4) hashalgs (2) 4
       }

       id-sha256    OBJECT IDENTIFIER ::= {
           joint-iso-itu-t (2) country (16) us (840) organization (1)
           gov (101) csor (3) nistalgorithm (4) hashalgs (2) 1
       }

       id-sha384    OBJECT IDENTIFIER ::= {
           joint-iso-itu-t (2) country (16) us (840) organization (1)
           gov (101) csor (3) nistalgorithm (4) hashalgs (2) 2
       }


       id-sha512    OBJECT IDENTIFIER ::= {
           joint-iso-itu-t (2) country (16) us (840) organization (1)
           gov (101) csor (3) nistalgorithm (4) hashalgs (2) 3
       }

       id-sha512-224    OBJECT IDENTIFIER ::= {
           joint-iso-itu-t (2) country (16) us (840) organization (1)
           gov (101) csor (3) nistalgorithm (4) hashalgs (2) 5
       }

       id-sha512-256    OBJECT IDENTIFIER ::= {
           joint-iso-itu-t (2) country (16) us (840) organization (1)
           gov (101) csor (3) nistalgorithm (4) hashalgs (2) 6
       }

   The parameters field associated with these OIDs in a value of type
   AlgorithmIdentifier SHALL have a value of type NULL.

   The parameters field associated with id-md2 and id-md5 in a value of
   type AlgorithmIdentifier shall have a value of type NULL.

   The parameters field associated with id-sha1, id-sha224, id-sha256,
   id-sha384, id-sha512, id-sha512/224, and id-sha512/256 should
   generally be omitted, but if present, it shall have a value of type
   NULL.

   This is to align with the definitions originally promulgated by NIST.
   For the SHA algorithms, implementations MUST accept
   AlgorithmIdentifier values both without parameters and with NULL
   parameters.

   Exception: When formatting the DigestInfoValue in EMSA-PKCS1-v1_5
   (see Section 9.2), the parameters field associated with id-sha1,
   id-sha224, id-sha256, id-sha384, id-sha512, id-sha512/224, and
   id-sha512/256 shall have a value of type NULL.  This is to maintain
   compatibility with existing implementations and with the numeric
   information values already published for EMSA-PKCS1-v1_5, which are
   also reflected in IEEE 1363a [IEEE1363A].

   Note: Version 1.5 of PKCS #1 also allowed for the use of MD4 in
   signature schemes.  The cryptanalysis of MD4 has progressed
   significantly in the intervening years.  For example, Dobbertin [MD4]
   demonstrated how to find collisions for MD4 and that the first two
   rounds of MD4 are not one-way [MD4FIRST].  Because of these results
   and others (e.g., [MD4LAST]), MD4 is NOT RECOMMENDED.

   Further advances have been made in the cryptanalysis of MD2 and MD5,
   especially after the findings of Stevens et al.  [PREFIX] on chosen-
   prefix collisions on MD5.  MD2 and MD5 should be considered
   cryptographically broken and removed from existing applications.
   This version of the standard supports MD2 and MD5 just for backwards-
   compatibility reasons.

   There have also been advances in the cryptanalysis of SHA-1.
   Particularly, the results of Wang et al.  [SHA1CRYPT] (which have
   been independently verified by M.  Cochran in his analysis [COCHRAN])
   on using a differential path to find collisions in SHA-1, which
   conclude that the security strength of the SHA-1 hashing algorithm is
   significantly reduced.  However, this reduction is not significant
   enough to warrant the removal of SHA-1 from existing applications,
   but its usage is only recommended for backwards-compatibility
   reasons.

   To address these concerns, only SHA-224, SHA-256, SHA-384, SHA-512,
   SHA-512/224, and SHA-512/256 are RECOMMENDED for new applications.
   As of today, the best (known) collision attacks against these hash
   functions are generic attacks with complexity 2L/2, where L is the
   bit length of the hash output.  For the signature schemes in this
   document, a collision attack is easily translated into a signature
   forgery.  Therefore, the value L / 2 should be at least equal to the
   desired security level in bits of the signature scheme (a security
   level of B bits means that the best attack has complexity 2B).  The
   same rule of thumb can be applied to RSAES-OAEP; it is RECOMMENDED
   that the bit length of the seed (which is equal to the bit length of
   the hash output) be twice the desired security level in bits.

##  Mask Generation Functions

   A mask generation function takes an octet string of variable length
   and a desired output length as input and outputs an octet string of
   the desired length.  There may be restrictions on the length of the
   input and output octet strings, but such bounds are generally very
   large.  Mask generation functions are deterministic; the octet string
   output is completely determined by the input octet string.  The
   output of a mask generation function should be pseudorandom: Given
   one part of the output but not the input, it should be infeasible to
   predict another part of the output.  The provable security of
   RSAES-OAEP and RSASSA-PSS relies on the random nature of the output
   of the mask generation function, which in turn relies on the random
   nature of the underlying hash.

   One mask generation function is given here: MGF1, which is based on a
   hash function.  MGF1 coincides with the mask generation functions
   defined in IEEE 1363 [IEEE1363] and ANSI X9.44 [ANSIX944].  Future
   versions of this document may define other mask generation functions.


## MGF1

   MGF1 is a mask generation function based on a hash function.

   MGF1 (mgfSeed, maskLen)

   Options:

      Hash     hash function (hLen denotes the length in octets of
               the hash function output)

   Input:

      mgfSeed  seed from which mask is generated, an octet string
      maskLen  intended length in octets of the mask, at most 2^32 hLen

   Output:

      mask     mask, an octet string of length maskLen

   Error: "mask too long"

   Steps:

   1.  If maskLen > 2^32 hLen, output "mask too long" and stop.

   2.  Let T be the empty octet string.

   3.  For counter from 0 to \ceil (maskLen / hLen) - 1, do the
       following:

       A.  Convert counter to an octet string C of length 4 octets (see
           Section 4.1):

              C = I2OSP (counter, 4) .

       B.  Concatenate the hash of the seed mgfSeed and C to the octet
           string T:

              T = T || Hash(mgfSeed || C) .

   4.  Output the leading maskLen octets of T as the octet string mask.

   The object identifier id-mgf1 identifies the MGF1 mask generation
   function:

      id-mgf1    OBJECT IDENTIFIER ::= { pkcs-1 8 }


   The parameters field associated with this OID in a value of type
   AlgorithmIdentifier shall have a value of type hashAlgorithm,
   identifying the hash function on which MGF1 is based.

## ASN.1 Module

    -- PKCS #1 v2.2 ASN.1 Module
    -- Revised October 27, 2012

    -- This module has been checked for conformance with the
    -- ASN.1 standard by the OSS ASN.1 Tools

    PKCS-1 {
        iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1)
        modules(0) pkcs-1(1)
    }

    DEFINITIONS EXPLICIT TAGS ::=

    BEGIN

    -- EXPORTS ALL
    -- All types and values defined in this module are exported for use
    -- in other ASN.1 modules.

    IMPORTS

    id-sha224, id-sha256, id-sha384, id-sha512, id-sha512-224,
    id-sha512-256
        FROM NIST-SHA2 {
            joint-iso-itu-t(2) country(16) us(840) organization(1)
            gov(101) csor(3) nistalgorithm(4) hashAlgs(2)
        };

    -- ============================
    --   Basic object identifiers
    -- ============================

    -- The DER encoding of this in hexadecimal is:
    -- (0x)06 08
    --        2A 86 48 86 F7 0D 01 01
    --
    pkcs-1    OBJECT IDENTIFIER ::= {
        iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1
    }

    --
    -- When rsaEncryption is used in an AlgorithmIdentifier,


    -- the parameters MUST be present and MUST be NULL.
    --
    rsaEncryption    OBJECT IDENTIFIER ::= { pkcs-1 1 }

    --
    -- When id-RSAES-OAEP is used in an AlgorithmIdentifier, the
    -- parameters MUST be present and MUST be RSAES-OAEP-params.
    --
    id-RSAES-OAEP    OBJECT IDENTIFIER ::= { pkcs-1 7 }

    --
    -- When id-pSpecified is used in an AlgorithmIdentifier, the
    -- parameters MUST be an OCTET STRING.
    --
    id-pSpecified    OBJECT IDENTIFIER ::= { pkcs-1 9 }

    --
    -- When id-RSASSA-PSS is used in an AlgorithmIdentifier, the
    -- parameters MUST be present and MUST be RSASSA-PSS-params.
    --
    id-RSASSA-PSS    OBJECT IDENTIFIER ::= { pkcs-1 10 }

    --
    -- When the following OIDs are used in an AlgorithmIdentifier,
    -- the parameters MUST be present and MUST be NULL.
    --
    md2WithRSAEncryption         OBJECT IDENTIFIER ::= { pkcs-1 2 }
    md5WithRSAEncryption         OBJECT IDENTIFIER ::= { pkcs-1 4 }
    sha1WithRSAEncryption        OBJECT IDENTIFIER ::= { pkcs-1 5 }
    sha224WithRSAEncryption      OBJECT IDENTIFIER ::= { pkcs-1 14 }
    sha256WithRSAEncryption      OBJECT IDENTIFIER ::= { pkcs-1 11 }
    sha384WithRSAEncryption      OBJECT IDENTIFIER ::= { pkcs-1 12 }
    sha512WithRSAEncryption      OBJECT IDENTIFIER ::= { pkcs-1 13 }
    sha512-224WithRSAEncryption  OBJECT IDENTIFIER ::= { pkcs-1 15 }
    sha512-256WithRSAEncryption  OBJECT IDENTIFIER ::= { pkcs-1 16 }

    --
    -- This OID really belongs in a module with the secsig OIDs.
    --
    id-sha1    OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2)
        26
    }

    --
    -- OIDs for MD2 and MD5, allowed only in EMSA-PKCS1-v1_5.
    --
    id-md2 OBJECT IDENTIFIER ::= {


       iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 2
   }

    id-md5 OBJECT IDENTIFIER ::= {
        iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 5
    }

    --
    -- When id-mgf1 is used in an AlgorithmIdentifier, the parameters
    -- MUST be present and MUST be a HashAlgorithm, for example, sha1.
    --
    id-mgf1    OBJECT IDENTIFIER ::= { pkcs-1 8 }

    -- ================
    --   Useful types
    -- ================

    ALGORITHM-IDENTIFIER ::= CLASS {
        &id    OBJECT IDENTIFIER  UNIQUE,
        &Type  OPTIONAL
    }
        WITH SYNTAX { OID &id [PARAMETERS &Type] }

    -- Note: the parameter InfoObjectSet in the following definitions
    -- allows a distinct information object set to be specified for sets
    -- of algorithms such as:
    -- DigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
    --     { OID id-md2  PARAMETERS NULL }|
    --     { OID id-md5  PARAMETERS NULL }|
    --     { OID id-sha1 PARAMETERS NULL }
    -- }
    --

    AlgorithmIdentifier { ALGORITHM-IDENTIFIER:InfoObjectSet } ::=
        SEQUENCE {
            algorithm
                ALGORITHM-IDENTIFIER.&id({InfoObjectSet}),
            parameters
                ALGORITHM-IDENTIFIER.&Type({InfoObjectSet}{@.algorithm})
                OPTIONAL
    }

    -- ==============
    --   Algorithms
    -- ==============

    --
    -- Allowed EME-OAEP and EMSA-PSS digest algorithms.

    --
    OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
        { OID id-sha1       PARAMETERS NULL }|
        { OID id-sha224     PARAMETERS NULL }|
        { OID id-sha256     PARAMETERS NULL }|
        { OID id-sha384     PARAMETERS NULL }|
        { OID id-sha512     PARAMETERS NULL }|
        { OID id-sha512-224 PARAMETERS NULL }|
        { OID id-sha512-256 PARAMETERS NULL },
        ...  -- Allows for future expansion --
    }

    --
    -- Allowed EMSA-PKCS1-v1_5 digest algorithms.
    --
    PKCS1-v1-5DigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
        { OID id-md2        PARAMETERS NULL }|
        { OID id-md5        PARAMETERS NULL }|
        { OID id-sha1       PARAMETERS NULL }|
        { OID id-sha224     PARAMETERS NULL }|
        { OID id-sha256     PARAMETERS NULL }|
        { OID id-sha384     PARAMETERS NULL }|
        { OID id-sha512     PARAMETERS NULL }|
        { OID id-sha512-224 PARAMETERS NULL }|
        { OID id-sha512-256 PARAMETERS NULL }
    }

    -- When id-md2 and id-md5 are used in an AlgorithmIdentifier, the
    -- parameters field shall have a value of type NULL.

    -- When id-sha1, id-sha224, id-sha256, id-sha384, id-sha512,
    -- id-sha512-224, and id-sha512-256 are used in an
    -- AlgorithmIdentifier, the parameters (which are optional) SHOULD be
    -- omitted, but if present, they SHALL have a value of type NULL.
    -- However, implementations MUST accept AlgorithmIdentifier values
    -- both without parameters and with NULL parameters.

    -- Exception: When formatting the DigestInfoValue in EMSA-PKCS1-v1_5
    -- (see Section 9.2), the parameters field associated with id-sha1,
    -- id-sha224, id-sha256, id-sha384, id-sha512, id-sha512-224, and
    -- id-sha512-256 SHALL have a value of type NULL.  This is to
    -- maintain compatibility with existing implementations and with the
    -- numeric information values already published for EMSA-PKCS1-v1_5,
    -- which are also reflected in IEEE 1363a.

    sha1    HashAlgorithm ::= {
        algorithm   id-sha1,
        parameters  SHA1Parameters : NULL
    }

    HashAlgorithm ::= AlgorithmIdentifier { {OAEP-PSSDigestAlgorithms} }

    SHA1Parameters ::= NULL

    --
    -- Allowed mask generation function algorithms.
    -- If the identifier is id-mgf1, the parameters are a HashAlgorithm.
    --
    PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
        { OID id-mgf1 PARAMETERS HashAlgorithm },
        ...  -- Allows for future expansion --
    }

    --
    -- Default AlgorithmIdentifier for id-RSAES-OAEP.maskGenAlgorithm and
    -- id-RSASSA-PSS.maskGenAlgorithm.
    --
    mgf1SHA1    MaskGenAlgorithm ::= {
        algorithm   id-mgf1,
        parameters  HashAlgorithm : sha1
    }

    MaskGenAlgorithm ::= AlgorithmIdentifier { {PKCS1MGFAlgorithms} }

    --
    -- Allowed algorithms for pSourceAlgorithm.
    --
    PKCS1PSourceAlgorithms    ALGORITHM-IDENTIFIER ::= {
        { OID id-pSpecified PARAMETERS EncodingParameters },
        ...  -- Allows for future expansion --
    }

    EncodingParameters ::= OCTET STRING(SIZE(0..MAX))

    --
    -- This identifier means that the label L is an empty string, so the
    -- digest of the empty string appears in the RSA block before
    -- masking.
    --

    pSpecifiedEmpty    PSourceAlgorithm ::= {
        algorithm   id-pSpecified,
        parameters  EncodingParameters : emptyString
    }

    PSourceAlgorithm ::= AlgorithmIdentifier { {PKCS1PSourceAlgorithms} }
    emptyString    EncodingParameters ::= ''H

    --
    -- Type identifier definitions for the PKCS #1 OIDs.
    --
    PKCS1Algorithms    ALGORITHM-IDENTIFIER ::= {
        { OID rsaEncryption                PARAMETERS NULL } |
        { OID md2WithRSAEncryption         PARAMETERS NULL } |
        { OID md5WithRSAEncryption         PARAMETERS NULL } |
        { OID sha1WithRSAEncryption        PARAMETERS NULL } |
        { OID sha224WithRSAEncryption      PARAMETERS NULL } |
        { OID sha256WithRSAEncryption      PARAMETERS NULL } |
        { OID sha384WithRSAEncryption      PARAMETERS NULL } |
        { OID sha512WithRSAEncryption      PARAMETERS NULL } |
        { OID sha512-224WithRSAEncryption  PARAMETERS NULL } |
        { OID sha512-256WithRSAEncryption  PARAMETERS NULL } |
        { OID id-RSAES-OAEP   PARAMETERS RSAES-OAEP-params } |
        PKCS1PSourceAlgorithms                               |
        { OID id-RSASSA-PSS   PARAMETERS RSASSA-PSS-params },
        ...  -- Allows for future expansion --
    }

    -- ===================
    --   Main structures
    -- ===================

    RSAPublicKey ::= SEQUENCE {
        modulus           INTEGER,  -- n
        publicExponent    INTEGER   -- e
    }

    --
    -- Representation of RSA private key with information for the CRT
    -- algorithm.
    --
    RSAPrivateKey ::= SEQUENCE {
        version           Version,
        modulus           INTEGER,  -- n
        publicExponent    INTEGER,  -- e
        privateExponent   INTEGER,  -- d
        prime1            INTEGER,  -- p
        prime2            INTEGER,  -- q
        exponent1         INTEGER,  -- d mod (p-1)
        exponent2         INTEGER,  -- d mod (q-1)
        coefficient       INTEGER,  -- (inverse of q) mod p
        otherPrimeInfos   OtherPrimeInfos OPTIONAL
    }


    Version ::= INTEGER { two-prime(0), multi(1) }
        (CONSTRAINED BY
            {-- version MUST
        be multi if otherPrimeInfos present --})

    OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo


    OtherPrimeInfo ::= SEQUENCE {
        prime             INTEGER,  -- ri
        exponent          INTEGER,  -- di
        coefficient       INTEGER   -- ti
    }

    --
    -- AlgorithmIdentifier.parameters for id-RSAES-OAEP.
    -- Note that the tags in this Sequence are explicit.
    --
    RSAES-OAEP-params ::= SEQUENCE {
        hashAlgorithm      [0] HashAlgorithm     DEFAULT sha1,
        maskGenAlgorithm   [1] MaskGenAlgorithm  DEFAULT mgf1SHA1,
        pSourceAlgorithm   [2] PSourceAlgorithm  DEFAULT pSpecifiedEmpty
    }

    --
    -- Identifier for default RSAES-OAEP algorithm identifier.
    -- The DER encoding of this is in hexadecimal:
    -- (0x)30 0D
    --        06 09
    --           2A 86 48 86 F7 0D 01 01 07
    --        30 00
    -- Notice that the DER encoding of default values is "empty".
    --

    rSAES-OAEP-Default-Identifier    RSAES-AlgorithmIdentifier ::= {
        algorithm   id-RSAES-OAEP,
        parameters  RSAES-OAEP-params : {
            hashAlgorithm       sha1,
            maskGenAlgorithm    mgf1SHA1,
            pSourceAlgorithm    pSpecifiedEmpty
        }
    }

    RSAES-AlgorithmIdentifier ::= AlgorithmIdentifier {
        {PKCS1Algorithms}
    }

    --


    -- AlgorithmIdentifier.parameters for id-RSASSA-PSS.
    -- Note that the tags in this Sequence are explicit.
    --
    RSASSA-PSS-params ::= SEQUENCE {
        hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
        maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
        saltLength         [2] INTEGER            DEFAULT 20,
        trailerField       [3] TrailerField       DEFAULT trailerFieldBC
    }

    TrailerField ::= INTEGER { trailerFieldBC(1) }

    --
    -- Identifier for default RSASSA-PSS algorithm identifier
    -- The DER encoding of this is in hexadecimal:
    -- (0x)30 0D
    --        06 09
    --           2A 86 48 86 F7 0D 01 01 0A
    --        30 00
    -- Notice that the DER encoding of default values is "empty".
    --
    rSASSA-PSS-Default-Identifier    RSASSA-AlgorithmIdentifier ::= {
        algorithm   id-RSASSA-PSS,
        parameters  RSASSA-PSS-params : {
            hashAlgorithm       sha1,
            maskGenAlgorithm    mgf1SHA1,
            saltLength          20,
            trailerField        trailerFieldBC
        }
    }

    RSASSA-AlgorithmIdentifier ::= AlgorithmIdentifier {
        {PKCS1Algorithms}
    }

    --
    -- Syntax for the EMSA-PKCS1-v1_5 hash identifier.
    --
    DigestInfo ::= SEQUENCE {
        digestAlgorithm DigestAlgorithm,
        digest OCTET STRING
    }

    DigestAlgorithm ::= AlgorithmIdentifier {
        {PKCS1-v1-5DigestAlgorithms}
    }

    END



Appendix D.  Revision History of PKCS #1

   Versions 1.0 - 1.5:

      Versions 1.0 - 1.3 were distributed to participants in RSA Data
      Security, Inc.'s Public-Key Cryptography Standards meetings in
      February and March 1991.

      Version 1.4 was part of the June 3, 1991 initial public release of
      PKCS.  Version 1.4 was published as NIST/OSI Implementors'
      Workshop document SEC-SIG-91-18.

      Version 1.5 incorporated several editorial changes, including
      updates to the references and the addition of a revision history.
      The following substantive changes were made:

      *  Section 10: "MD4 with RSA" signature and verification processes
         were added.

      *  Section 11: md4WithRSAEncryption object identifier was added.

      Version 1.5 was republished as [RFC2313] (which was later
      obsoleted by [RFC2437]).

   Version 2.0:

      Version 2.0 incorporated major editorial changes in terms of the
      document structure and introduced the RSAES-OAEP encryption
      scheme.  This version continued to support the encryption and
      signature processes in version 1.5, although the hash algorithm
      MD4 was no longer allowed due to cryptanalytic advances in the
      intervening years.  Version 2.0 was republished as [RFC2437]
      (which was later obsoleted by [RFC3447]).

   Version 2.1:

      Version 2.1 introduced multi-prime RSA and the RSASSA-PSS
      signature scheme with appendix along with several editorial
      improvements.  This version continued to support the schemes in
      version 2.0.  Version 2.1 was republished as [RFC3447].


   Version 2.2:

      Version 2.2 updates the list of allowed hashing algorithms to
      align them with FIPS 180-4 [SHS], therefore adding SHA-224,
      SHA-512/224, and SHA-512/256.  The following substantive changes
      were made:

      *  Object identifiers for sha224WithRSAEncryption,
         sha512-224WithRSAEncryption, and sha512-256WithRSAEncryption
         were added.

      *  This version continues to support the schemes in version 2.1.
