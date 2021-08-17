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

[Link to PKCS #1](https://datatracker.ietf.org/doc/html/rfc8017)


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
The hash value is *padded*: a byte sequence is assembled, consisting of, in that order: a byte of value 0x00, a byte of value 0x01, some bytes of value 0xFF, a byte of value 0x00, a fixed header sequence H, and then $`h(m)`$. The header sequence $`H`$ identifies the hash function. The number of 0xFF bytes is adjusted so that the total sequence length is exactly equal to the encoding length of the modulus (i.e. 128 bytes for a 1024-bit modulus).

    So the resulting padded sequence looks like the following:

        0x00 | 0x01 | 0xFF .. 0xFF | 0x00 | H | h(m)

- The padded value is then interpreted as an integer $`x`$, by decoding it with the big-endian convention. Due to the sequence size and the fact that the sequence begins with a 0x00, the value $`x`$ is necessarily in the $`1..n−1`$ range.

- The value $`x`$ is raised to the power d (private exponent) modulo n, yielding $`s = x^d(\mod n)`$

- The $`s`$ value is encoded into a sequence of the same length as n, forming the signature.

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

   2. Let $`x = x_{xLen-1} 256^{xLen-1} + x_{xLen-2} 256^{xLen-2} + ... + x_1 256 + x_0`$.

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


**EMSA-PSS-ENCODE (M, emBits)**

   **Options:**

      Hash     hash function (hLen denotes the length in octets of
               the hash function output)
      MGF      mask generation function
      sLen     intended length in octets of the salt

   **Input:**

      M        message to be encoded, an octet string
      emBits   maximal bit length of the integer OS2IP (EM), at least 8hLen + 8sLen + 9

   **Output:**

      EM       encoded message, an octet string of length emLen = \ceil
               (emBits/8)

   **Errors:**  "Encoding error"; "message too long"

   **Steps:**

      1.   If the length of M is greater than the input limitation for
           the hash function (2^61 - 1 octets for SHA-1), output
           "message too long" and stop.

      2.   Let mHash = Hash(M), an octet string of length hLen.

      3.   If emLen < hLen + sLen + 2, output "encoding error" and stop.

      4.   Generate a random octet string salt of length sLen; if sLen =
           0, then salt is the empty string.

      5.   Let

              M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;

           M' is an octet string of length 8 + hLen + sLen with eight
           initial zero octets.

      6.   Let H = Hash(M'), an octet string of length hLen.

      7.   Generate an octet string PS consisting of emLen - sLen - hLen
           - 2 zero octets.  The length of PS may be 0.

      8.   Let DB = PS || 0x01 || salt; DB is an octet string of length
           emLen - hLen - 1.

      9.   Let dbMask = MGF(H, emLen - hLen - 1).

      10.  Let maskedDB = DB \xor dbMask.

      11.  Set the leftmost 8emLen - emBits bits of the leftmost octet
           in maskedDB to zero.

      12.  Let EM = maskedDB || H || 0xbc.

      13.  Output EM.

   **RSASP1 (K, m)**  

**Input:**  

        K        RSA private key, where K has one of the following forms:
                - a pair (n, d)
                - a quintuple (p, q, dP, dQ, qInv) and a (possibly empty)
                    sequence of triplets (r_i, d_i, t_i), i = 3, ..., u
        m        message representative, an integer between 0 and n - 1


**Output:**  

        s        signature representative, an integer between 0 and n - 1

**Error:**  "message representative out of range"  

**Assumption:**  RSA private key K is valid  

**Steps:**

        1.  If the message representative m is not between 0 and n - 1,
            output "message representative out of range" and stop.

        2.  The signature representative s is computed as follows.

            a.  If the first form (n, d) of K is used, let s = m^d mod n.

            b.  If the second form (p, q, dP, dQ, qInv) and (r_i, d_i,
                t_i) of K is used, proceed as follows:

                1.  Let s_1 = m^dP mod p and s_2 = m^dQ mod q.

                2.  If u > 2, let s_i = m^(d_i) mod r_i, i = 3, ..., u.

                3.  Let h = (s_1 - s_2) * qInv mod p.

                4.  Let s = s_2 + q * h.

                5.  If u > 2, let R = r_1 and for i = 3 to u do

                    a.  Let R = R * r_(i-1).

                    b.  Let h = (s_i - s) * t_i mod r_i.

                    c.  Let s = s + R * h.

        3.  Output s.

    Note: Step 2.b can be rewritten as a single loop, provided that one
    reverses the order of p and q.  For consistency with PKCS #1 v2.0,
    however, the first two primes p and q are treated separately from the
    additional primes.

### **Signature generation operation**

**RSASSA-PSS-SIGN (K, M)**

**Input:**
    K        signer's RSA private key
    M        message to be signed, an octet string

**Output:**
    S        signature, an octet string of length k, where k is the
                length in octets of the RSA modulus n

**Errors:** "message too long;" "encoding error"

   **Steps:**

   1. EMSA-PSS encoding: Apply the EMSA-PSS encoding operation to the message M to produce an encoded message EM of length
      $`\lceil ((modBits - 1)/8)\rceil`$ octets such that the bit length of the
      integer OS2IP (EM) is at most modBits - 1, where
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

      - Apply the RSASP1 signature primitive to the RSA
         private key K and the message representative m to produce an
         integer signature representative s:

            s = RSASP1 (K, m).

      - Convert the signature representative s to a signature S of
         length k octets:

            S = I2OSP (s, k).

   3. Output the signature S.

### **Signature verification operation**
**RSASSA-PSS-VERIFY ((n, e), M, S)**

**Input:**
    (n, e)   signer's RSA public key
    M        message whose signature is to be verified, an octet string
    S        signature to be verified, an octet string of length k, where
                k is the length in octets of the RSA modulus n

**Output:**
    "valid signature" or "invalid signature"

**Steps:**

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
      to the message M and the encoded message EM to
      determine whether they are consistent:

            Result = EMSA-PSS-VERIFY (M, EM, modBits - 1).

   4. If Result = "consistent," output "valid signature." Otherwise,
      output "invalid signature."


**RSAVP1 ((n, e), s)**  

**Input:**  

            (n, e) RSA public key  

            s signature representative, an integer between 0 and n - 1  

**Output:**  

            m message representative, an integer between 0 and n - 1  

**Error:**  "signature representative out of range"  

**Assumption:**  RSA public key (n, e) is valid  

**Steps:**

        1.  If the signature representative s is not between 0 and n - 1,
            output "signature representative out of range" and stop.

        2.  Let m = s^e mod n.

        3.  Output m.

**EMSA-PSS-VERIFY (M, EM, emBits)**

   **Options:**  

      Hash     hash function (hLen denotes the length in octets of
               the hash function output)
      MGF      mask generation function
      sLen     intended length in octets of the salt

   **Input:**  

      M        message to be verified, an octet string
      EM       encoded message, an octet string of length emLen = \ceil
               (emBits/8)
      emBits   maximal bit length of the integer OS2IP (EM) (see Section
               4.2), at least 8hLen + 8sLen + 9

   **Output:**  "consistent" or "inconsistent"  

   **Steps:**  

      1.   If the length of M is greater than the input limitation for
           the hash function (2^61 - 1 octets for SHA-1), output
           "inconsistent" and stop.

      2.   Let mHash = Hash(M), an octet string of length hLen.

      3.   If emLen < hLen + sLen + 2, output "inconsistent" and stop.

      4.   If the rightmost octet of EM does not have hexadecimal value
           0xbc, output "inconsistent" and stop.

      5.   Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
           and let H be the next hLen octets.

      6.   If the leftmost 8emLen - emBits bits of the leftmost octet in
           maskedDB are not all equal to zero, output "inconsistent" and
           stop.

      7.   Let dbMask = MGF(H, emLen - hLen - 1).

      8.   Let DB = maskedDB \xor dbMask.

      9.   Set the leftmost 8emLen - emBits bits of the leftmost octet
           in DB to zero.

      10.  If the emLen - hLen - sLen - 2 leftmost octets of DB are not
           zero or if the octet at position emLen - hLen - sLen - 1 (the
           leftmost position is "position 1") does not have hexadecimal
           value 0x01, output "inconsistent" and stop.

      11.  Let salt be the last sLen octets of DB.

      12.  Let

              M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;

           M' is an octet string of length 8 + hLen + sLen with eight
           initial zero octets.

      13.  Let H' = Hash(M'), an octet string of length hLen.

      14.  If H = H', output "consistent".  Otherwise, output
           "inconsistent".

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

   To address these concerns, only SHA-224, SHA-256, SHA-384, SHA-512,
   SHA-512/224, and SHA-512/256 are RECOMMENDED for new applications.
   As of today, the best (known) collision attacks against these hash
   functions are generic attacks with complexity 2L/2, where L is the
   bit length of the hash output.  For the signature schemes in this
   document, a collision attack is easily translated into a signature
   forgery.  Therefore, the value L / 2 should be at least equal to the
   desired security level in bits of the signature scheme (a security
   level of B bits means that the best attack has complexity 2B). 

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

   **Options:**

      Hash     hash function (hLen denotes the length in octets of
               the hash function output)

   **Input:**

      mgfSeed  seed from which mask is generated, an octet string
      maskLen  intended length in octets of the mask, at most 2^32 hLen

   **Output:**

      mask     mask, an octet string of length maskLen

   **Error:** "mask too long"

  **Steps:**

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