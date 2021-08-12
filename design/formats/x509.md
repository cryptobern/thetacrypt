# X.509 Standard
[reference](https://datatracker.ietf.org/doc/html/rfc5280) <br>
X.509 is a standard defining the format of public key certificates. X.509 certificates are used in many Internet protocols, including TLS/SSL. They are also used in offline applications, like electronic signatures.

## X.509 Certificate Format
A X.509 certificate has the following format:

    Certificate  ::=  SEQUENCE  {
            tbsCertificate       TBSCertificate,
            signatureAlgorithm   AlgorithmIdentifier,
            signatureValue       BIT STRING  }

    AlgorithmIdentifier  ::=  SEQUENCE  {
            algorithm            OBJECT IDENTIFIER,
            parameters           ANY DEFINED BY algorithm OPTIONAL  }

The sequence `TBSCertificate` contains information associated with the
subject of the certificate and the CA that issued it.  Every
`TBSCertificate` contains the names of the subject and issuer, a public
key associated with the subject, a validity period, a version number,
and a serial number; some MAY contain optional unique identifier
fields.  A `TBSCertificate` usually includes
extensions.  <br>

## TBSCertificate  

    TBSCertificate  ::=  SEQUENCE  {
            version         [0]  EXPLICIT Version DEFAULT v1,
            serialNumber         CertificateSerialNumber,
            signature            AlgorithmIdentifier,
            issuer               Name,
            validity             Validity,
            subject              Name,
            subjectPublicKeyInfo SubjectPublicKeyInfo,
            issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                                -- If present, version MUST be v2 or v3
            subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                                -- If present, version MUST be v2 or v3
            extensions      [3]  EXPLICIT Extensions OPTIONAL
                                -- If present, version MUST be v3
            }
    
    Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

The `version` field describes the version of the encoded certificate.  When
   extensions are used, as expected in this profile, version MUST be 3
   (value is 2).  If no extensions are present, but a `UniqueIdentifier`
   is present, the version SHOULD be 2 (value is 1); however, the
   version MAY be 3.  If only basic fields are present, the version
   SHOULD be 1 (the value is omitted from the certificate as the default
   value); however, the version MAY be 2 or 3. Implementations SHOULD be prepared to accept any version certificate.
   At a minimum, conforming implementations MUST recognize version 3
   certificates.

    CertificateSerialNumber  ::=  INTEGER

The `serialNumber` MUST be a positive integer assigned by the CA to
   each certificate.  It MUST be unique for each certificate issued by a
   given CA (i.e., the issuer name and serial number identify a unique
   certificate).  CAs MUST force the `serialNumber` to be a non-negative
   integer. Certificate users MUST be able to
   handle `serialNumber` values up to 20 octets.  Conforming CAs MUST NOT
   use `serialNumber` values longer than 20 octets.
   Note: Non-conforming CAs may issue certificates with serial numbers
   that are negative or zero.  Certificate users SHOULD be prepared to
   gracefully handle such certificates.  

The `signature` field contains the algorithm identifier for the algorithm used
   by the CA to sign the certificate. This field MUST contain the same algorithm identifier as the
   `signatureAlgorithm` field in the sequence `Certificate`. The contents of the optional parameters field will vary
   according to the algorithm identified. 
   
The `issuer` field identifies the entity that has signed and issued the
   certificate.  The issuer field MUST contain a non-empty distinguished
   name (DN).  The issuer field is defined as the X.501 type `Name` which is defined by the following ASN.1 structures:


    Name ::= CHOICE { -- only one possibility for now --
        rdnSequence  RDNSequence }

    RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

    RelativeDistinguishedName ::=
        SET SIZE (1..MAX) OF AttributeTypeAndValue

    AttributeTypeAndValue ::= SEQUENCE {
        type     AttributeType,
        value    AttributeValue }
    
    AttributeType ::= OBJECT IDENTIFIER

    AttributeValue ::= ANY -- DEFINED BY AttributeType


The `Name` describes a hierarchical name composed of attributes, such
as country name, and corresponding values, such as US.  The type of
the component AttributeValue is determined by the AttributeType; in
general it will be a `DirectoryString`. This
specification does not restrict the set of attribute types that may
appear in names.  However, conforming implementations MUST be
prepared to receive certificates with issuer names containing the set
of attribute types defined below.  This specification RECOMMENDS
support for additional attribute types.


    DirectoryString ::= CHOICE {
            teletexString           TeletexString (SIZE (1..MAX)),
            printableString         PrintableString (SIZE (1..MAX)),
            universalString         UniversalString (SIZE (1..MAX)),
            utf8String              UTF8String (SIZE (1..MAX)),
            bmpString               BMPString (SIZE (1..MAX)) }


Standard sets of attributes have been defined in the X.500 series of
specifications [X.520].  Implementations of this specification MUST
be prepared to receive the following standard attribute types in
issuer and subject names:

- country,
- organization,
- organizational unit,
- distinguished name qualifier,
- state or province name,
- common name (e.g., "Susan Housley"), and
- serial number.

In addition, implementations of this specification SHOULD be prepared
to receive the following standard attribute types in issuer and
subject names:

- locality,
- title,
- surname,
- given name,
- initials,
- pseudonym, and
- generation qualifier (e.g., "Jr.", "3rd", or "IV").

<br>

The `validity` field specifies the validity period of the certificate. The certificate validity period is the time interval during which the
CA warrants that it will maintain information about the status of the
certificate.  The field `validity` is represented as a SEQUENCE of two dates:
the date on which the certificate validity period begins (`notBefore`)
and the date on which the certificate validity period ends
(`notAfter`).  Both `notBefore` and `notAfter` may be encoded as UTCTime or
GeneralizedTime. <br>

    Validity ::= SEQUENCE {
            notBefore      Time,
            notAfter       Time }

    
    Time ::= CHOICE {
            utcTime        UTCTime,
            generalTime    GeneralizedTime }

CAs conforming to this profile MUST always encode certificate
validity dates through the year 2049 as UTCTime; certificate validity
dates in 2050 or later MUST be encoded as GeneralizedTime.
Conforming applications MUST be able to process validity dates that
are encoded in either UTCTime or GeneralizedTime.

To indicate that a certificate has no well-defined expiration date,
the `notAfter` SHOULD be assigned the GeneralizedTime value of
99991231235959Z.

The `subject` field identifies the entity associated with the public
key stored in the subject public key field.  The subject name MAY be
carried in the `subject` field and/or the `subjectAltName` extension. It is defined as the X.501 type `Name`. Where it is non-empty, the subject field MUST contain an X.500 distinguished name (DN).  The DN MUST be unique for each subject
   entity certified by the one CA as defined by the issuer field.  A CA
   MAY issue more than one certificate with the same DN to the same
   subject entity.

The `subjectPublicKeyInfo` is used to carry the public key and identify the algorithm
with which the key is used (e.g., RSA, DSA, or Diffie-Hellman).  The
algorithm is identified using the AlgorithmIdentifier structure.

    SubjectPublicKeyInfo  ::=  SEQUENCE  {
                algorithm            AlgorithmIdentifier,
                subjectPublicKey     BIT STRING  }


   The unique identifier fields MUST only appear if the version is 2 or 3.  These fields MUST NOT appear if the version is 1.  The
   subject and issuer unique identifiers are present in the certificate
   to handle the possibility of reuse of subject and/or issuer names
   over time.  This profile RECOMMENDS that names not be reused for
   different entities and that Internet certificates not make use of
   unique identifiers.  CAs conforming to this profile MUST NOT generate
   certificates with unique identifiers.  Applications conforming to this profile SHOULD be capable of parsing certificates that include
   unique identifiers, but there are no processing requirements
   associated with the unique identifiers.

   The `extension` field MUST only appear if the version is 3.
   If present, this field is a SEQUENCE of one or more certificate
   extensions.

    Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

    Extension  ::=  SEQUENCE  {
            extnID      OBJECT IDENTIFIER,
            critical    BOOLEAN DEFAULT FALSE,
            extnValue   OCTET STRING
                        -- contains the DER encoding of an ASN.1 value
                        -- corresponding to the extension type identified
                        -- by extnID
            }


The `signatureValue` is encoded as a bit string and the format depends on the signature algorithm used. RSA for example uses the format defined in PKCS #1.

# Example Certificate using DSA Signature
   This section contains an annotated hex dump of a 914-byte version 3
   certificate.  The certificate contains the following information:

   (a)  the serial number is 256;

   (b)  the certificate is signed with DSA and the SHA-1 hash algorithm;

   (c)  the issuer's distinguished name is cn=Example DSA
        CA,dc=example,dc=com;

   (d)  the subject's distinguished name is cn=DSA End
        Entity,dc=example,dc=com;

   (e)  the certificate was issued on May 2, 2004 and expired on May 2,
        2005;

   (f)  the certificate contains a 1024-bit DSA public key with
        parameters;

   (g)  the certificate is an end entity certificate (not a CA
        certificate);

   (h)  the certificate includes a subject alternative name of
        "<http://www.example.com/users/DSAendentity.html>" and an issuer
        alternative name of "<http://www.example.com>" -- both are URLs;

   (i)  the certificate includes an authority key identifier extension
        and a certificate policies extension specifying the policy OID
        2.16.840.1.101.3.2.1.48.9; and

   (j)  the certificate includes a critical key usage extension
        specifying that the public key is intended for verification of
        digital signatures.

    0    910: SEQUENCE {
    4    846:   SEQUENCE {
    8      3:     [0] {
    10     1:       INTEGER 2
            :       }
    13     2:     INTEGER 256
    17     9:     SEQUENCE {
    19     7:       OBJECT IDENTIFIER dsaWithSha1 (1 2 840 10040 4 3)
            :       }
    28    71:     SEQUENCE {
    30    19:       SET {
    32    17:         SEQUENCE {
    34    10:           OBJECT IDENTIFIER
            :             domainComponent (0 9 2342 19200300 100 1 25)
    46     3:           IA5String 'com'
            :           }
            :         }
    51    23:       SET {
    53    21:         SEQUENCE {
    55    10:           OBJECT IDENTIFIER
            :             domainComponent (0 9 2342 19200300 100 1 25)
    67     7:           IA5String 'example'
            :           }
            :         }
    76    23:       SET {
    78    21:         SEQUENCE {
    80     3:           OBJECT IDENTIFIER commonName (2 5 4 3)
    85    14:           PrintableString 'Example DSA CA'
            :           }
            :         }
            :       }
    101   30:     SEQUENCE {
    103   13:       UTCTime 02/05/2004 16:47:38 GMT
    118   13:       UTCTime 02/05/2005 16:47:38 GMT
            :       }
    133   71:     SEQUENCE {
    135   19:       SET {
    137   17:         SEQUENCE {
    139   10:           OBJECT IDENTIFIER
            :             domainComponent (0 9 2342 19200300 100 1 25)
    151    3:           IA5String 'com'
            :           }
            :         }
    156   23:       SET {
    158   21:         SEQUENCE {
    160   10:           OBJECT IDENTIFIER
            :             domainComponent (0 9 2342 19200300 100 1 25)
    172    7:           IA5String 'example'
            :           }
            :         }
    181   23:       SET {
    183   21:         SEQUENCE {
    185    3:           OBJECT IDENTIFIER commonName (2 5 4 3)
    190   14:           PrintableString 'DSA End Entity'
            :           }
            :         }
            :       }
    206  439:     SEQUENCE {
    210  300:       SEQUENCE {
    214    7:         OBJECT IDENTIFIER dsa (1 2 840 10040 4 1)
    223  287:         SEQUENCE {
    227  129:           INTEGER
            :             00 B6 8B 0F 94 2B 9A CE A5 25 C6 F2 ED FC FB 95
            :             32 AC 01 12 33 B9 E0 1C AD 90 9B BC 48 54 9E F3
            :             94 77 3C 2C 71 35 55 E6 FE 4F 22 CB D5 D8 3E 89
            :             93 33 4D FC BD 4F 41 64 3E A2 98 70 EC 31 B4 50
            :             DE EB F1 98 28 0A C9 3E 44 B3 FD 22 97 96 83 D0
            :             18 A3 E3 BD 35 5B FF EE A3 21 72 6A 7B 96 DA B9
            :             3F 1E 5A 90 AF 24 D6 20 F0 0D 21 A7 D4 02 B9 1A
            :             FC AC 21 FB 9E 94 9E 4B 42 45 9E 6A B2 48 63 FE
            :             43
    359   21:           INTEGER
            :             00 B2 0D B0 B1 01 DF 0C 66 24 FC 13 92 BA 55 F7
            :             7D 57 74 81 E5
    382  129:           INTEGER
            :             00 9A BF 46 B1 F5 3F 44 3D C9 A5 65 FB 91 C0 8E
            :             47 F1 0A C3 01 47 C2 44 42 36 A9 92 81 DE 57 C5
            :             E0 68 86 58 00 7B 1F F9 9B 77 A1 C5 10 A5 80 91
            :             78 51 51 3C F6 FC FC CC 46 C6 81 78 92 84 3D F4
            :             93 3D 0C 38 7E 1A 5B 99 4E AB 14 64 F6 0C 21 22
            :             4E 28 08 9C 92 B9 66 9F 40 E8 95 F6 D5 31 2A EF
            :             39 A2 62 C7 B2 6D 9E 58 C4 3A A8 11 81 84 6D AF
            :             F8 B4 19 B4 C2 11 AE D0 22 3B AA 20 7F EE 1E 57
            :             18
            :           }
            :         }
    514  132:       BIT STRING, encapsulates {
    518  128:         INTEGER
            :           30 B6 75 F7 7C 20 31 AE 38 BB 7E 0D 2B AB A0 9C
            :           4B DF 20 D5 24 13 3C CD 98 E5 5F 6C B7 C1 BA 4A
            :           BA A9 95 80 53 F0 0D 72 DC 33 37 F4 01 0B F5 04
            :           1F 9D 2E 1F 62 D8 84 3A 9B 25 09 5A 2D C8 46 8E
            :           2B D4 F5 0D 3B C7 2D C6 6C B9 98 C1 25 3A 44 4E
            :           8E CA 95 61 35 7C CE 15 31 5C 23 13 1E A2 05 D1
            :           7A 24 1C CB D3 72 09 90 FF 9B 9D 28 C0 A1 0A EC
            :           46 9F 0D B8 D0 DC D0 18 A6 2B 5E F9 8F B5 95 BE
            :         }
            :       }
    649  202:     [3] {
    652  199:       SEQUENCE {
    655   57:         SEQUENCE {
    657    3:           OBJECT IDENTIFIER subjectAltName (2 5 29 17)
    662   50:           OCTET STRING, encapsulates {
    664   48:             SEQUENCE {
    666   46:               [6]
            :                 'http://www.example.com/users/DSAendentity.'
            :                 'html'
            :               }
            :             }
            :           }
    714   33:         SEQUENCE {
    716    3:           OBJECT IDENTIFIER issuerAltName (2 5 29 18)
    721   26:           OCTET STRING, encapsulates {
    723   24:             SEQUENCE {
    725   22:               [6] 'http://www.example.com'
            :               }
            :             }
            :           }
    749   29:         SEQUENCE {
    751    3:           OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
    756   22:           OCTET STRING, encapsulates {
    758   20:             OCTET STRING
            :               DD 25 66 96 43 AB 78 11 43 44 FE 95 16 F9 D9 B6
            :               B7 02 66 8D
            :             }
            :           }
    780   31:         SEQUENCE {
    782    3:           OBJECT IDENTIFIER
            :             authorityKeyIdentifier (2 5 29 35)
    787   24:           OCTET STRING, encapsulates {
    789   22:             SEQUENCE {
    791   20:               [0]
            :                 86 CA A5 22 81 62 EF AD 0A 89 BC AD 72 41 2C
            :                 29 49 F4 86 56
            :               }
            :             }
            :           }
    813   23:         SEQUENCE {
    815    3:           OBJECT IDENTIFIER certificatePolicies (2 5 29 32)
    820   16:           OCTET STRING, encapsulates {
    822   14:             SEQUENCE {
    824   12:               SEQUENCE {
    826   10:                 OBJECT IDENTIFIER '2 16 840 1 101 3 2 1 48 9'
            :                 }
            :               }
            :             }
            :           }
    838   14:         SEQUENCE {
    840    3:           OBJECT IDENTIFIER keyUsage (2 5 29 15)
    845    1:           BOOLEAN TRUE
    848    4:           OCTET STRING, encapsulates {
    850    2:             BIT STRING 7 unused bits
            :               '1'B (bit 0)
            :             }
            :           }
            :         }
            :       }
            :     }
    854    9:   SEQUENCE {
    856    7:     OBJECT IDENTIFIER dsaWithSha1 (1 2 840 10040 4 3)
            :     }
    865   47:   BIT STRING, encapsulates {
    868   44:     SEQUENCE {
    870   20:       INTEGER
            :         65 57 07 34 DD DC CA CC 5E F4 02 F4 56 42 2C 5E
            :         E1 B3 3B 80
    892   20:       INTEGER
            :         60 F4 31 17 CA F4 CF FF EE F4 08 A7 D9 B2 61 BE
            :         B1 C3 DA BF
            :       }
            :     }
            :   }