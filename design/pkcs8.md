# PKCS #8
PKCS8 is the eighth of the Public-Key Cryptography Standards (PKCS) and is a syntax for storing private key material. The private keys may be encrypted with a symmetric key algorithm. If the usage of your key requires it to be in plain text, make sure it is stored in a secured location. If at all possible, keep the PKCS #8 formatted private key encrypted. PKCS #8 was defined in [this standard](https://datatracker.ietf.org/doc/html/rfc5208). <br>

The header and footer of the PKCS #8 syntax is the following:

    -----BEGIN PRIVATE KEY-----
    -----END PRIVATE KEY-----

…and if the PKCS #8 formatted private key is encrypted, the header and footer is the following:

    -----BEGIN ENCRYPTED PRIVATE KEY-----
    -----END ENCRYPTED PRIVATE KEY-----

This format is pem formatted.

PKCS#8 uses [PEM encoding](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/design/encoding.md) to encode the ASN.1 objects. 

## **PKCS #8 vs PKCS #1**
PKCS #1 in contrast is primarily used to store private keys for the RSA algorithm. Some applications may even load private key information from a private key entry in a PKCS12 formatted keystore which is also common. But, many languages expect a single file and not a keystore, which makes PKCS #8 a suitable syntax.

## **PKCS #8 vs PKCS #12**

These are two different specs, and PKCS #12 is meant to bundle a key pair with a certificate and not to store a single PKCS #8 private key. While a PKCS #12 formatted keystore is password protected, so should the stand alone PKCS#8 private key if at all possible. This also goes for a PKCS #1 private key. Both private key formats should have a symmetric key encrypting them at rest.

## **X.509 Definitions**
[X.509](https://www.itu.int/rec/T-REC-X.509-198811-S) defines the following fields, needed later in this document

    Certificate ::= SIGNED SEQUENCE { 
        version            [0]  Version DEFAULT 1988, 
        serialNumber            SerialNumber, 
        signature               Algorithmidentifier 
        issuer                  Name 
        validity                Validity, 
        subject                 Name, 
        subjectPublicKeyInfo    SubjectPublicKeyInfo } 

    Version     ::= INTEGER { 1988(0) } 

    SerialNumber ::= INTEGER 

    Validity      ::= SEQUENCE {  
        notBefore UTCTime, 
        notAfter  UTCTime }

    SubjectPublicKeyInfo ::= SEQUENCE { 
        algorithm AlgorithmIdentifier 
        subjectKey BIT STRING }

    AlgorithmIdentifier ::= SEQUENCE { 
        algorithm   OBJECT IDENTIFIER 
        parameters   ANY DEFINED BY algorithm  OPTIONAL }


## **Unencrypted Private-Key Information Syntax**
This section gives the syntax for private-key information.
Private-key information shall have ASN.1 type PrivateKeyInfo:

      PrivateKeyInfo ::= SEQUENCE {
        version                   Version,
        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        privateKey                PrivateKey,
        attributes           [0]  IMPLICIT Attributes OPTIONAL }

      Version ::= INTEGER

      PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier

      PrivateKey ::= OCTET STRING

      Attributes ::= SET OF Attribute

 The fields of type PrivateKeyInfo have the following meanings:

- `version` is the syntax version number, for compatibility with
future revisions of this document.  It shall be 0 for this version
of the document.

- `privateKeyAlgorithm` identifies the private-key algorithm.  One
      example of a private-key algorithm is PKCS #1's rsaEncryption.

- `privateKey` is an octet string whose contents are the value of the
      private key.  The interpretation of the contents is defined in the
      registration of the private-key algorithm.  For an RSA private
      key, for example, the contents are a BER encoding of a value of
      type RSAPrivateKey.

- `attributes` is a set of attributes.  These are the extended
      information that is encrypted along with the private-key
      information.

## **Encrypted Private-Key Information Syntax**

   This section gives the syntax for encrypted private-key information. Encrypted private-key information shall have ASN.1 type
   EncryptedPrivateKeyInfo:

    EncryptedPrivateKeyInfo ::= SEQUENCE {
        encryptionAlgorithm  EncryptionAlgorithmIdentifier,
        encryptedData        EncryptedData }

    EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier

    EncryptedData ::= OCTET STRING

   The fields of type `EncryptedPrivateKeyInfo` have the following
   meanings:

- `encryptionAlgorithm` identifies the algorithm under which the
    private-key information is encrypted.  Two examples are PKCS #5's
    pbeWithMD2AndDES-CBC and pbeWithMD5AndDES-CBC [PKCS#5].

- `encryptedData` is the result of encrypting the private-key
    information.

The encryption process involves the following two steps:

1. The private-key information is BER encoded, yielding an octet
    string.

2. The result of step 1 is encrypted with the secret key to give
    an octet string, the result of the encryption process.

## **Security Considerations**

   Protection of the private-key information is vital to public-key
   cryptography.  Disclosure of the private-key material to another
   entity can lead to masquerades.  The encryption algorithm used in the
   encryption process must be as 'strong' as the key it is protecting.
