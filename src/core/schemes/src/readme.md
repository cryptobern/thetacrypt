## ThetaCrypt - Schemes (src)
The directory structure of this layer is as follows:

- bin:          contains a binary to generate generators for an elliptic curve group
- dl_schemes:   contains all discrete logarithm based schemes and groups
- rsa_schemes:  contains all schemes and groups based on the RSA problem
- examples:     contains examples on how to use the schemes layer

Also, these are the most important files: 
- group.rs      - provides the abstract Group enum to be used in schemes implementations
- keys.rs       - provides a wrapper and generator for the different keys
- interface.rs  - defines the main traits and structs for the schemes layer
- rand.rs       - contains pseudo-randomness generators (if you're not sure which one to use, it is recommended to use `RngAlgorithm::OsRng`)

