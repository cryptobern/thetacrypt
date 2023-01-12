# Threshold Crypto Library Design
![](./img/overview.svg) <br>
This documentation is split into three layers. On layer 2, the schemes layer, are the concrete schemes described. On layer 1, the format layer, are different ways to represent outputs and inputs of the schemes on layer 2, and layer 0, the encoding layer, specifies how those inputs/outputs are serialized into bytes.
## **Overview**
- [Definition of a Party](party.md)
- [Schemes](schemes/)
    - [DL Schemes](schemes/dl_schemes.md) - Discrete logarithm based threshold schemes
    - [RSA Schemes](schemes/rsa_schemes.md) - RSA based threshold schemes
- [Formats](formats/)
    - [PKCS #1](formats/pkcs1.md) - RSA formats for keys/signatures
    - [PKCS #8](formats/pkcs8.md) - Generic format for private keys
    - [X.509](formats/X.509.md) - X.509 Certificate format
- [Encoding](encoding/)
    - [ASN.1](encoding/asn1.md) - BER/DER/PER Encoding 
    - [IEEE 1363](encoding/ieee1363.md) - Elliptic curve point representation
    - [SEC](encoding/sec.md) - ECDSA Encoding
