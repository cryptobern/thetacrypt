# Standards of Efficient Cryptography (SEC)
[reference](https://secg.org/sec1-v2.pdf) <br>

## Syntax for Elliptic Curve Domain Parameters
Elliptic curve domain parameters may need to be specified, for example, during the setup operation of a cryptographic scheme based on elliptic curve cryptography. There are a number of
ways of specifying elliptic curve domain parameters. Here the following syntax, as a choice of
three parameters, is recommended (following [3279, Int06b, 5480]) for use in X.509 certificates and
elsewhere.

    ECDomainParameters{ECDOMAIN:IOSet} ::= CHOICE {
        specified SpecifiedECDomain,
        named ECDOMAIN.&id({IOSet}),
        implicitCA NULL
    }
The choice of three parameters representation methods (above) allows detailed specification of all
required values using either:
- The choice `specified` which explicitly identifies all the parameters, or,
- The choice `named` as an object identifier identifying a particular set of elliptic curve domain
parameters, or
- The choice `implicitCA` which indicates that the parameters are the same as those of certification authority certifying the public key.
The valid values for the namedCurve choice are constrained to those within the class `ECDOMAIN`
(defined below).

The following syntax is used to describe explicit representations of elliptic curve domain parameters,
if need be. The inclusion of the cofactor is strongly recommended.

        SpecifiedECDomain ::= SEQUENCE {
        version SpecifiedECDomainVersion(ecdpVer1 | ecdpVer2 | ecdpVer3, ...),
        fieldID FieldID {{FieldTypes}},
        curve Curve,
        base ECPoint,
        order INTEGER,
        cofactor INTEGER OPTIONAL,
        hash HashAlgorithm OPTIONAL,
        ...
        }

The components of type `SpecifiedECDomain` have the following meanings.
- The component `version` is the version number of the ASN.1 type with a value of 1, 2 or 3.
The notation above is used to constrain version to a set of values. The meaning of these
three values are as follows. If version is ecdpVer2, then the curve and the base point shall
be generated verifiably at random, and curve.seed shall be present. If version is ecdpVer3,
then the curve is not generated verifiably at random but the base point is, and curve.seed
shall be present.
- The component `fieldID` identifies the finite field over which the elliptic curve is defined and
was discussed in Section C.1.
- The component `curve` of type `Curve` (defined below) specifies the elliptic curve.
- The component `base` of type `ECPoint` (defined below) specifies the base point on the elliptic
curve curve.
- The component `order` is the order of the base point base.
- The component `cofactor` is the order of the curve divided by the order of the base point.
Inclusion of the cofactor is optional – however, it is recommended that that the cofactor be
included in order to facilitate interoperability between implementations.
- The component `hash` is the hash function used to generate the domain parameters verifiably
at random.

The type `SpecifiedECDomainVersion` is a subtype of INTEGER and is used to constrain the set of
versions.

    SpecifiedECDomainVersion ::= INTEGER {
    ecdpVer1(1),
    ecdpVer2(2),
    ecdpVer3(3)
    }
The type `Curve` is defined as follows, by specifying the coefficients of the defining equation of the
elliptic curve and an optional seed. (If the curve was generated verifiably at random using a seed
value with a hash function such as SHA-1 as specified in ANS X9.62 [X9.62b] then said seed may
be included as the seed component so as to allow a recipient to verify that the curve was indeed
so generated using said seed.)

    Curve ::= SEQUENCE {
    a FieldElement,
    b FieldElement,
    seed BIT STRING OPTIONAL
    -- Shall be present if used in SpecifiedECDomain
    -- with version equal to ecdpVer2 or ecdpVer3
    }
An elliptic curve point itself is represented by the following type

    ECPoint ::= OCTET STRING
whose value is the octet string obtained from the conversion routines given in [ieee1363](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/design/encoding/ieee1363.md).
The class `ECDOMAIN`, defined as follows, is used to specify a named curve.

    ECDOMAIN ::= CLASS {
    &id OBJECT IDENTIFIER UNIQUE
    }
    WITH SYNTAX { ID &id }

For example, the curve sect163k1, defined in SEC 2 [SEC 2], is denoted by the syntax ID
sect163k1.
The following syntax, included here for completeness, may be extended by other standards and
implementations to specify the list of supported named curves. One such extension may be found
in SEC 2 [SEC 2] ; another such extension may be found in ANS X9.62 [X9.62b].

    SECGCurveNames ECDOMAIN::= {
    ... -- named curves
    }
The following type `HashAlgorithm` is used to specify a hash function.

    HashAlgorithm ::= AlgorithmIdentifier {{ HashFunctions }}
The information object set `HashFunctions` specifies the allowed hash functions currently:

    HashFunctions ALGORITHM ::= {
    {OID sha-1 PARMS NULL } |
    {OID id-sha224 PARMS NULL } |
    {OID id-sha256 PARMS NULL } |
    {OID id-sha384 PARMS NULL } |
    {OID id-sha512 PARMS NULL } ,
    ... -- Additional hash functions may be added in the future }
When the parameters field of `HashAlgorithm` is constrained to the type NULL, then the parameters
should be omitted.
The following object identifiers are used above to identify specific hash functions.

    sha-1 OBJECT IDENTIFIER ::= {iso(1) identified-organization(3)
    oiw(14) secsig(3) algorithm(2) 26}
    id-sha OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840)
    organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) }
    id-sha224 OBJECT IDENTIFIER ::= { id-sha 4 }
    id-sha256 OBJECT IDENTIFIER ::= { id-sha 1 }
    id-sha384 OBJECT IDENTIFIER ::= { id-sha 2 }
    id-sha512 OBJECT IDENTIFIER ::= { id-sha 3 }

## Syntax for Elliptic Curve Public Keys
Elliptic curve public keys may need to be specified, for example, during the key deployment phase
of a cryptographic scheme based on elliptic curve cryptography. An elliptic curve public key is a
point on an elliptic curve and may be represented in a variety of ways using ASN.1 syntax. Here
the following syntax is recommended (following [3279, Int06b, 5480]) for use in X.509 certificates
and elsewhere, where public keys are represented by the ASN.1 type SubjectPublicKeyInfo.

    SubjectPublicKeyInfo ::= SEQUENCE {
        algorithm AlgorithmIdentifier {{ECPKAlgorithms}} (WITH COMPONENTS
        {algorithm, parameters}) ,
        subjectPublicKey BIT STRING
    }

The component algorithm specifies the type of public key and associated parameters employed and the component subjectPublicKey specifies the actual value of said public key.
The parameter type `AlgorithmIdentifier` above tightly binds together a set of algorithm object
identifiers and their associated parameters types. The type `AlgorithmIdentifier` is defined as
follows.

    AlgorithmIdentifier{ ALGORITHM:IOSet } ::= SEQUENCE {
    algorithm ALGORITHM.&id({IOSet}),
    parameters ALGORITHM.&Type({IOSet}{@algorithm}) OPTIONAL
    }

The governing type ALGORITHM (above) is defined to be the following object information object.

    ALGORITHM ::= CLASS {
        &id OBJECT IDENTIFIER UNIQUE,
        &Type OPTIONAL
        }
        WITH SYNTAX { OID &id [PARMS &Type] }
        ECPKAlgorithms ALGORITHM ::= {
        ecPublicKeyType |
        ecPublicKeyTypeRestricted |
        ecPublicKeyTypeSupplemented |
        {OID ecdh PARMS ECDomainParameters {{SECGCurveNames}}} |
        {OID ecmqv PARMS ECDomainParameters {{SECGCurveNames}}},
        ...
    }

    ecPublicKeyType ALGORITHM ::= {
        OID id-ecPublicKey PARMS ECDomainParameters {{SECGCurveNames}}
    }

The object identifier id-ecPublicKey designates an elliptic curve public key. It is defined by the
following (after ANS X9.62 [X9.62b]) to be used whenever an object identifier for an elliptic curve
public key is needed. (Note that this syntax applies to all elliptic curve public keys regardless of
their designated use.)

    id-ecPublicKey OBJECT IDENTIFIER ::= { id-publicKeyType 1 }
where

    id-publicKeyType OBJECT IDENTIFIER ::= { ansi-X9-62 keyType(2) }
The following information object of class ALGORITHM indicates the type of the parameters component of an AlgorithmIdentifier {} containing the OID id-ecPublicKeyRestricted.

    ecPublicKeyTypeRestricted ALGORITHM ::= {
    OID id-ecPublicKeyTypeRestricted PARMS ECPKRestrictions
    }
The OID id-ecPublicKeyTypeRestricted is used to identify a public key that has restrictions on
which ECC algorithms it can be used with.

    id-ecPublicKeyTypeRestricted OBJECT IDENTIFIER ::= {
    id-publicKeyType restricted(2) }

The type ECPKRestrictions identifies the restrictions on the algorithms that can be used with a
    given elliptic curve public key.

    ECPKRestrictions ::= SEQUENCE {
        ecDomain ECDomainParameters {{ SECGCurveNames }},
        eccAlgorithms ECCAlgorithms
    }
The type ECCAlgorithms is used to identify one or more ECC algorithms, possibly, but not necessarily, in an order of preference.

    ECCAlgorithms ::= SEQUENCE OF ECCAlgorithm

The type ECCAlgorithm is a constrained instance of the parameterized type `AlgorithmIdentifier`
{}, and is used to identify an ECC algorithm.

    ECCAlgorithm ::= AlgorithmIdentifier {{ECCAlgorithmSet}}

When the optional parameters field of ECCAlgorithm is constrained to the type NULL, then it
should be omitted. When the optional parameters field is constrained to a type other than NULL,
then it should be present.
The component `ECDomainParameters` was defined in Section C.2 and may contain the elliptic curve
domain parameters associated with the public key in question. (Thus the component algorithm
indicates that `SubjectPublicKeyInfo` not only specifies the elliptic curve public key but also the
elliptic curve domain parameters associated with said public key.)
Finally, `SubjectPublicKeyInfo` specifies the public key itself when algorithm indicates that the
public key is an elliptic curve public key.
The elliptic curve public key (a value of type ECPoint that is an OCTET STRING) is mapped to a
`subjectPublicKey` (a value encoded as type BIT STRING) as follows: The most significant bit of
the value of the OCTET STRING becomes the most significant bit of the value of the BIT STRING
and so on with consecutive bits until the least significant bit of the OCTET STRING becomes the
least significant bit of the BIT STRING.
The following information object of class ALGORITHM indicates the type of the paramaters component of an `AlgorithmIdentifier` {} containing the OID `id-ecPublicKeySupplemented`.

    ecPublicKeyTypeSupplemented ALGORITHM ::= {
    OID id-ecPublicKeyTypeSupplemented PARMS ECPKSupplements
    }
The OID id-`ecPublicKeyTypeSupplemented` is used to identify a public key that has restrictions
on which ECC algorithms it can be used with.

    secg-scheme OBJECT IDENTIFIER ::= { iso(1)
        identified-organization(3) certicom(132) schemes(1) }
        id-ecPublicKeyTypeSupplemented OBJECT IDENTIFIER ::= {
        secg-scheme supplementalPoints(0) }
The type `ECPKSupplements` identifies the supplements (and restrictions) on the algorithms that
can be used with a given elliptic curve public key.

    ECPKSupplements ::= SEQUENCE {
        ecDomain ECDomainParameters {{ SECGCurveNames }},
        eccAlgorithms ECCAlgorithms,
        eccSupplements ECCSupplements }
The type ECCSupplements serves to provide a list of multiples of the public key. These multiples
can be used to accelerate the public key operations necessary with that public key.
    ECCSupplements ::= CHOICE {
        namedMultiples [0] NamedMultiples,
        specifiedMultiples [1] SpecifiedMultiples
    }
    NamedMultiples ::= SEQUENCE {
        multiples OBJECT IDENTIFIER,
        points SEQUENCE OF ECPoint }
        SpecifiedMultiples ::= SEQUENCE OF SEQUENCE {
        multiple INTEGER,
        point ECPoint }

## Syntax for Elliptic Curve Private Keys
An elliptic curve private key may need to be conveyed, for example, during the key deployment
operation of a cryptographic scheme in which a Certification Authority generates and distributes
the private keys. An elliptic curve private key is an unsigned integer. The following ASN.1 syntax
may be used.

    ECPrivateKey ::= SEQUENCE {
    version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    privateKey OCTET STRING,
    parameters [0] ECDomainParameters {{ SECGCurveNames }} OPTIONAL,
    publicKey [1] BIT STRING OPTIONAL
    }
where  
- The component version specifies the version number of the elliptic curve private key structure. The syntax above creates the element ecPrivkeyVer1 of type INTEGER whose value is 1.  

- The component privateKey is the private key defined to be the octet string of length
dlog2 n/8e (where n is the order of the curve) obtained from the unsigned integer via the
encoding of Section 2.3.7.  

- The optional component parameters specifies the elliptic curve domain parameters associated
to the private key. The type Parameters was discussed in Section C.2. If the parameters are
known by other means then this component may be NULL or omitted.  

- The optional component publicKey contains the elliptic curve public key associated with the
private key in question. Public keys were discussed in Section C.3. It may be useful to send
the public key along with the private key, especially in a scheme such as MQV that involves
calculations with the public key.  

The syntax for `ECPrivateKey` may be used, for example, to convey elliptic curve private keys using
the syntax for PrivateKeyInfo as defined in PKCS #8 [PKCS8]. In such a case, the value of the
component `privateKeyAlgorithm` within `PrivateKeyInfo` shall be `id-ecPublicKey` as discussed
in the section above.

## Syntax for Signature and Key Establishment Schemes
Signatures may need to be conveyed from one party to another whenever ECDSA is used to sign
a message. The following syntax is recommended to represent actual signatures for use within
X.509 certificates, CRLs, and elsewhere. The signature is conveyed using the parameterized type `SIGNED`. It comprises the specification of an algorithm of type
`AlgorithmIdentifier` together with the actual signature
When the signature is generated using ECDSA with SHA-1, the algorithm component shall contain
the object identifier ecdsa-with-SHA1 (defined below) and the parameters component shall either
contain NULL or be absent. The parameters component should be omitted.

    ecdsa-with-SHA1 OBJECT IDENTIFIER ::= { id-ecSigType sha1(1)}
    ecdsa-with-Recommended OBJECT IDENTIFIER ::= { id-ecSigType recommended(2) }
    ecdsa-with-Specified OBJECT IDENTIFIER ::= { id-ecSigType specified(3)}
    ecdsa-with-Sha224 OBJECT IDENTIFIER ::= { id-ecSigType specified(3) 1 }
    ecdsa-with-Sha256 OBJECT IDENTIFIER ::= { id-ecSigType specified(3) 2 }
    ecdsa-with-Sha384 OBJECT IDENTIFIER ::= { id-ecSigType specified(3) 3 }
    ecdsa-with-Sha512 OBJECT IDENTIFIER ::= { id-ecSigType specified(3) 4 }
    id-ecSigType OBJECT IDENTIFIER ::= { ansi-X9-62 signatures(4) }

The information object set ECDSAAlgorithmSet specifies how the object identifiers above are to
be used in algorithm identifiers and also serves to constrain the set of algorithms specifiable in this
ASN.1 syntax, when using ECDSA.

    ECDSAAlgorithmSet ALGORITHM ::= {
    {OID ecdsa-with-SHA1 PARMS NULL} |
    {OID ecdsa-with-Recommended PARMS NULL} |
    {OID ecdsa-with-Specified PARMS HashAlgorithm } |
    {OID ecdsa-with-Sha224 PARMS NULL} |
    {OID ecdsa-with-Sha256 PARMS NULL} |
    {OID ecdsa-with-Sha384 PARMS NULL} |
    {OID ecdsa-with-Sha512 PARMS NULL} ,
    ... -- More algorithms need to be added
    }
The information object set ECCAlgorithmSet specifies the ECC algorithms that can be identified
with this syntax.

    ECCAlgorithmSet ALGORITHM ::= {
    ECDSAAlgorithmSet |
    ECDHAlgorithmSet |
    ECMQVAlgorithmSet |
    ECIESAlgorithmSet |
    ECWKTAlgorithmSet ,
    ...
    }
The information object set ECDHAlgorithmSet used above is defined below.

    ECDHAlgorithmSet ALGORITHM ::= {
    {OID dhSinglePass-stdDH-sha1kdf PARMS NULL} |
    {OID dhSinglePass-cofactorDH-sha1kdf PARMS NULL} |
    {OID dhSinglePass-cofactorDH-recommendedKDF} |
    {OID dhSinglePass-cofactorDH-specifiedKDF PARMS KeyDerivationFunction} |
    {OID ecdh} |
    {OID dhSinglePass-stdDH-sha256kdf-scheme} |
    {OID dhSinglePass-stdDH-sha384kdf-scheme} |
    {OID dhSinglePass-stdDH-sha224kdf-scheme} |
    {OID dhSinglePass-stdDH-sha512kdf-scheme} |
    {OID dhSinglePass-cofactorDH-sha256kdf-scheme} |
    {OID dhSinglePass-cofactorDH-sha384kdf-scheme} |
    {OID dhSinglePass-cofactorDH-sha224kdf-scheme} |
    {OID dhSinglePass-cofactorDH-sha512kdf-scheme} ,
    ... -- Future combinations may be added
    }

The information object set ECMQVHAlgorithmSet used above is defined below.

    ECMQVAlgorithmSet ALGORITHM ::= {
    {OID mqvSinglePass-sha1kdf} |
    {OID mqvSinglePass-recommendedKDF} |
    {OID mqvSinglePass-specifiedKDF PARMS KeyDerivationFunction} |
    {OID mqvFull-sha1kdf} |
    {OID mqvFull-recommendedKDF} |
    {OID mqvFull-specifiedKDF PARMS KeyDerivationFunction} |
    {OID ecmqv} |
    {OID mqvSinglePass-sha256kdf-scheme } |
    {OID mqvSinglePass-sha384kdf-scheme } |
    {OID mqvSinglePass-sha224kdf-scheme } |
    {OID mqvSinglePass-sha512kdf-scheme } |
    {OID mqvFull-sha256kdf-scheme } |
    {OID mqvFull-sha384kdf-scheme } |
    {OID mqvFull-sha224kdf-scheme } |
    {OID mqvFull-sha512kdf-scheme } ,
    ... -- Future combinations may be added
    }
The object identifiers used in the two information object sets above are given below.

    x9-63-scheme OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    us(840) ansi-x9-63(63) schemes(0) }
    dhSinglePass-stdDH-sha1kdf OBJECT IDENTIFIER ::= {x9-63-scheme 2}
    dhSinglePass-cofactorDH-sha1kdf OBJECT IDENTIFIER ::= {x9-63-scheme 3}
    mqvSinglePass-sha1kdf OBJECT IDENTIFIER ::= {x9-63-scheme 16}
    mqvFull-sha1kdf OBJECT IDENTIFIER ::= {x9-63-scheme 17}
    dhSinglePass-cofactorDH-recommendedKDF OBJECT IDENTIFIER ::= {secg-scheme 1}
    dhSinglePass-cofactorDH-specifiedKDF OBJECT IDENTIFIER ::= {secg-scheme 2}
    ecdh OBJECT IDENTIFIER ::= {secg-scheme 12}
    dhSinglePass-stdDH-sha256kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 11 1}
    dhSinglePass-stdDH-sha384kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 11 2}
    dhSinglePass-stdDH-sha224kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 11 0}
    dhSinglePass-stdDH-sha512kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 11 3}
    dhSinglePass-cofactorDH-sha256kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 14 1}
    dhSinglePass-cofactorDH-sha384kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 14 2}
    dhSinglePass-cofactorDH-sha224kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 14 0}
    dhSinglePass-cofactorDH-sha512kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 14 3}
    mqvSinglePass-recommendedKDF OBJECT IDENTIFIER ::= {secg-scheme 3}
    mqvSinglePass-specifiedKDF OBJECT IDENTIFIER ::= {secg-scheme 4}
    mqvFull-recommendedKDF OBJECT IDENTIFIER ::= {secg-scheme 5}
    mqvFull-specifiedKDF OBJECT IDENTIFIER ::= {secg-scheme 6}
    ecmqv OBJECT IDENTIFIER ::= {secg-scheme 13}
    mqvSinglePass-sha256kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 15 1}
    mqvSinglePass-sha384kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 15 2}
    mqvSinglePass-sha224kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 15 0}
    mqvSinglePass-sha512kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 15 3}
    mqvFull-sha256kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 16 1}
    mqvFull-sha384kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 16 2}
    mqvFull-sha224kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 16 0}
    mqvFull-sha512kdf-scheme OBJECT IDENTIFIER ::= {secg-scheme 16 3}

The object identifiers above that end in recommendedKDF indicated that key derivation to use is
the default for the associated elliptic curve domain parameters. The object identifiers ecdh and
ecmqv are meant for very general indication, with other details to be specified out of band.
The type KeyDerivationFunction is given below.

    KeyDerivationFunction ::= AlgorithmIdentifier {{KDFSet}}
    KDFSet ALGORITHM ::= {
    {OID x9-63-kdf PARMS HashAlgorithm } |
    {OID nist-concatenation-kdf PARMS HashAlgorithm } |
    {OID tls-kdf PARMS HashAlgorithm } |
    {OID ikev2-kdf PARMS HashAlgorithm } ,
    ... -- Future combinations may be added
    }
    x9-63-kdf OBJECT IDENTIFIER ::= {secg-scheme 17 0}
    nist-concatenation-kdf OBJECT IDENTIFIER ::= {secg-scheme 17 1}
    tls-kdf OBJECT IDENTIFIER ::= {secg-scheme 17 2}
    ikev2-kdf OBJECT IDENTIFIER ::= {secg-scheme 17 3}

The information object set `ECIESAlgorithmSet` specifies how one identifies ECIES.

    ECIESAlgorithmSet ALGORITHM ::= {
    {OID ecies-recommendedParameters} |
    {OID ecies-specifiedParameters PARMS ECIESParameters} ,
    ... -- Future combinations may be added
    }
The object identifiers given above are:

    ecies-recommendedParameters OBJECT IDENTIFIER ::= {secg-scheme 7}
    ecies-specifiedParameters OBJECT IDENTIFIER ::= {secg-scheme 8}
    The type ECIESParameters is defined below.
    ECIESParameters ::= SEQUENCE {
    kdf [0] KeyDerivationFunction OPTIONAL,
    sym [1] SymmetricEncryption OPTIONAL,
    mac [2] MessageAuthenticationCode OPTIONAL
    }

    SymmetricEncryption ::= AlgorithmIdentifier {{SYMENCSet}}
    MessageAuthenticationCode ::= AlgorithmIdentifier {{MACSet}}
    SYMENCSet ALGORITHM ::= {
    { OID xor-in-ecies } |
    { OID tdes-cbc-in-ecies } |
    { OID aes128-cbc-in-ecies } |
    { OID aes192-cbc-in-ecies } |
    { OID aes256-cbc-in-ecies } |
    { OID aes128-ctr-in-ecies } |
    { OID aes192-ctr-in-ecies } |
    { OID aes256-ctr-in-ecies } ,
    ... -- Future combinations may be added
    }
    MACSet ALGORITHM ::= {
    { OID hmac-full-ecies PARMS HashAlgorithm} |
    { OID hmac-half-ecies PARMS HashAlgorithm} |
    { OID cmac-aes128-ecies } |
    { OID cmac-aes192-ecies } |
    { OID cmac-aes256-ecies } ,
    ... -- Future combinations may be added
    }
    xor-in-ecies OBJECT IDENTIFIER ::= {secg-scheme 18 }
    tdes-cbc-in-ecies OBJECT IDENTIFIER ::= {secg-scheme 19 }
    aes128-cbc-in-ecies OBJECT IDENTIFIER ::= {secg-scheme 20 0 }
    aes192-cbc-in-ecies OBJECT IDENTIFIER ::= {secg-scheme 20 1 }
    aes256-cbc-in-ecies OBJECT IDENTIFIER ::= {secg-scheme 20 2 }
    aes128-ctr-in-ecies OBJECT IDENTIFIER ::= {secg-scheme 21 0 }
    aes192-ctr-in-ecies OBJECT IDENTIFIER ::= {secg-scheme 21 1 }
    aes256-ctr-in-ecies OBJECT IDENTIFIER ::= {secg-scheme 21 2 }
    hmac-full-ecies OBJECT IDENTIFIER ::= {secg-scheme 22 }
    hmac-half-ecies OBJECT IDENTIFIER ::= {secg-scheme 23 }
    cmac-aes128-ecies OBJECT IDENTIFIER ::= {secg-scheme 24 0 }
    cmac-aes192-ecies OBJECT IDENTIFIER ::= {secg-scheme 24 1 }
    cmac-aes256-ecies OBJECT IDENTIFIER ::= {secg-scheme 24 2 }

The information object set ECWKTAlgorithmSet specifies how one identifies elliptic curve wrapped
key transport, if one is using the scheme as a single unit, not as a combination of the key agreement scheme and key wrap scheme. Typically, one may identify a wrapped key transport scheme
separately as a combination of a key agreement schemes and key wrap scheme.

    ECWKTAlgorithmSet ALGORITHM ::= {
    {OID ecwkt-recommendedParameters} |
    {OID ecwkt-specifiedParameters PARMS ECWKTParameters} ,
    ... -- Future combinations may be added
    }

The object identifiers given above are:
    ecwkt-recommendedParameters OBJECT IDENTIFIER ::= {secg-scheme 9}
    ecwkt-specifiedParameters OBJECT IDENTIFIER ::= {secg-scheme 10}

The type ECWKTParameters are defined below.

    ECWKTParameters ::= SEQUENCE {
    kdf [0] KeyDerivationFunction OPTIONAL,
    wrap [1] KeyWrapFunction OPTIONAL
    }
    KeyWrapFunction ::= AlgorithmIdentifier {{KeyWrapSet}}
    KeyWrapSet ALGORITHM ::= {
    { OID aes128-key-wrap } |
    { OID aes192-key-wrap } |
    { OID aes256-key-wrap } ,
    ... -- Future combinations may be added
    }
    aes128-key-wrap OBJECT IDENTIFIER ::= {secg-scheme 25 0 }
    aes192-key-wrap OBJECT IDENTIFIER ::= {secg-scheme 25 1 }
    aes256-key-wrap OBJECT IDENTIFIER ::= {secg-scheme 25 2 }
The actual value of an ECDSA signature, that is, a signature identified by ecdsa-with-SHA1 or
any other of the above identifiers for ECDSA, is encoded as follows.

    ECDSA-Signature ::= CHOICE {
    two-ints-plus ECDSA-Sig-Value,
    point-int [0] ECDSA-Full-R,
    ... -- Future representations may be added
    }

Note the first choice is a type compatible with the previous version of this standard. The second
choice is an alternative format, which aims to provide a simpler means to aid accelerated methods
of ECDSA verification. Because both choice alternative syntaxes are sequences and the rules of
ASN.1 dictate that choices have different tags, the second choice has been tagged. The first choice
is not tagged so that old signature will appear to comply.
The original syntax ECDSA-Sig-Value has been extended to allow for additional information to be
attached which the verifier can use recover the value of R from r, permitting accelerated signature
verification.

    ECDSA-Sig-Value ::= SEQUENCE {
        r INTEGER,
        s INTEGER,
        a INTEGER OPTIONAL,
        y CHOICE { b BOOLEAN, f FieldElement } OPTIONAL
    }
The alternative syntax for identifying an ECDSA signature value explicit includes the point R
represented as an octet string.

    ECDSA-Full-R ::= SEQUENCE {
        r ECPoint,
        s INTEGER
    }

X.509 certificates and CRLs represent a signature as a bit string; in such cases, the entire encoding
of a value of ECDSA-Signature is the value of said bit string.
The actual value of an ECIES ciphertext may be encoded in ASN.1 with the following type.

    ECIES-Ciphertext-Value ::= SEQUENCE {
        ephemeralPublicKey ECPoint,
        symmetricCiphertext OCTET STRING,
        macTag OCTET STRING
    }