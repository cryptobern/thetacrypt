# Thetacrypt - Threshold Cryptography Distributed Service in Rust

Thetacrypt is a WIP codebase that aims at providing **threshold cryptography** as a service.

- To dive into the details of the architecture of our service explore the `src` directory.
- To try a quick start and immediately explore the functionalities offered by Thetacrypt, check the `demo` directory.
- To learn more about threshold cryptography and its theoretical background, remain on this page.

## Theoretical background

### What is threshold cryptography?

Threshold cryptography defines protocols to enhance the security of a cryptographic scheme by distributing the trust among a group of parties. 
Typically, it is used for sharing a secret across a predefined number of nodes so as to obtain fault-tolerance for a subset, 
or *threshold*, of them. 
More formally, a threshold cryptosystem is defined by a fixed number of parties $P = \{P_1, \dots, P_n\}$, who need to collaborate to perform a cryptographic operation such that at least a threshold of them, $(t+1)$-out-of- $n$, are able to successfully terminate, but $t$ will learn anything about the shared secret. 
This is achieved by using *Shamir's secret sharing*, i.e. a technique based on *polynomial interpolation* that enables the reconstruction 
of a polynomial of degree $t$ with at least $t+1$ points.


The generation and distribution of a secret $s$ is performed, in the easiest setting, by a trusted dealer $D$ $\notin P$. The dealer chooses at random the coefficients
$\{a_1, \dots, a_t\}$ and defines the polynomial: $p(x) = s + a_1 x + \dots + a_t x^t$. The polynomial has a degree at most $t$ and its evaluation 
in $p(0)$ is the secret. The polynomial will be uniquely determined by $t+1$ point.

Threshold cryptosystems are known for public-key schemes only, where applying secret sharing is possible thanks to the algebraic assumption used in such schemes.

## Implemented Schemes and References

| Scheme Name  | Scheme Type            | Reference                                                                                                                                                                          |
|--------------|------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SG02         | Cryptosystem           | [Securing Threshold Cryptosystems against Chosen Ciphertext Attack](https://link.springer.com/content/pdf/10.1007/s00145-001-0020-9.pdf) (ZK-based)                                |
| BZ03         | Cryptosystem           | [Simple and Efficient Threshold Cryptosystem from the Gap Diffie-Hellman Group](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=1258486) (Pairing-based)                  |
| BLS04        | Signature              | [Short Signatures from the Weil Pairing](https://www.iacr.org/archive/asiacrypt2001/22480516.pdf) (Pairing-based)                                                                  |
| FROST        | Signature              | [FROST: Flexible Round-Optimized Schnorr Threshold Signatures](https://eprint.iacr.org/2020/852.pdf) (ZK-based)                                                                    |     
| SHOO         | Signature              | [Practical Threshold Signatures](https://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf) (Threshold RSA)                                                                 |
| CKS05        | Coin-flip              | [Random Oracles in Constantinople: Practical Asynchronous Byzantine Agreement Using Cryptography](https://link.springer.com/content/pdf/10.1007/s00145-005-0318-0.pdf) (ZK-based)  |

