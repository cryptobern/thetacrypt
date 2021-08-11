# Threshold Crypto Library Design
![](./img/overview.svg) <br>
This documentation is split into three layers. On layer 2, the schemes layer, are the concrete schemes described. On layer 1, the format layer, are different ways to represent outputs and inputs of the schemes on layer 2 and layer 0, the encoding layer, specifies how those inputs/outputs are serialized as bytes.
## **Overview**
- [Interface](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/design/interface.md)
- [Definition of a Party](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/design/party.md)
- [Schemes](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/design/schemes/)
    - [DL Schemes](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/design/schemes/dl_schemes.md)
- [Formats](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/design/formats/)
    - [PKCS #1](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/design/formats/pkcs1.md) - RSA formats for keys/signatures
    - [PKCS #8](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/design/formats/pkcs8.md) - Generic format for private keys
- [Encoding](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/design/encoding/)
    - [ASN.1](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/design/encoding/asn1.md) - BER/DER/PER Encoding 
    - [IEEE 1363](https://gitlab.inf.unibe.ch/crypto/2021.cosmoscrypto/-/blob/master/design/encoding/ieee1363.md) - Elliptic curve point representation
