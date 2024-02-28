# ThetaCrypt - Threshold Cryptography Library in Rust

Thetacrypt is a WIP codebase that aims at providing **threshold cryptography** as a service.

- To dive into the details of the architecture of our service explore the `src` directory.
- To try a quick start and immediately explore the functionalities offered by thetacrypt, check the `demo` directory.
- To learn more about threshold cryptography and its theoretical background, remain on this page.

## Theoretical background 

### What is threshold cryptography?

Threshold cryptography defines protocols to enhance the security of a cryptosystem by distributing the trust among a group of parties. 
Typically, it is used for sharing a secret across a predefined number of nodes so as to obtain fault-tolerance for a subset, 
or *threshold*, of them. 
More formally, a threshold cryptosystem is defined by a fixed number of parties $P = \{P_1, \dots, P_n\}$, who need to collaborate to perform a cryptographic operation such that at least a threshold of them, $(t+1)$-out-of- $n$, are able to successfully terminate, but $t$ will learn anything about the shared secret. 
This is achieved by using *Shamir's secret sharing*, i.e. a technique based on *polynomial interpolation* that enables the reconstruction 
of a polynomial of degree $t$ with at least $t+1$ points.


The generation and distribution of the secret $s$ are performed, in the easiest setting, by a trusted dealer $D$  $\notin P$. The dealer chooses at random the coefficients
$\{a_1, \dots, a_t\}$  and defines the polynomial: $p\(x\) = s + a_1 x + \dots + a_t x^t$. The polynomial has a degree at most $t$ and its evaluation 
in $p(0)$ is the secret. The polynomial will be uniquely determined by $t+1$ point. 

Threshold cryptosystems are known for public-key schemes only, where applying secret sharing is possible thanks to the algebraic assumption used in such schemes. 
