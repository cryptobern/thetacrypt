# ThetaCrypt - Threshold Cryptography in Rust

This library is split into three main parts:
- The **schemes** layer: Implements the various threshold cryptography schemes
- The **protocols** layer: Uses the primitives from the schemes layer to create threshold cryptography protocols.
- The **network** layer: Used to exchange peer-to-peer messages between the participating parties.

## Client Development
One can import the `schemes` layer in a Rust application to for example use the primitives required to encrypt data to submit for threshold decryption or verify signatures created using a threshold signature scheme. 

## ThetaCLI
Alternatively, there exists a CLI application which can be used to encrypt files and generate keys. Use `cargo run --bin thetacli` to build and run the CLI application. 
Usage: `./thetacli [action] [params]`
available actions:
- `keygen [k] [n] [algorithms] [directory]` \
  generates the public/private keys for the specified schemes and groups \
  `k` = threshold \
  `n` = number of private keys \
  `directory` = directory to store generated keys in \
  `algorithms` = a list of comma separated elements of the format `'scheme-group'`, where <br> `'scheme'` is one of the following: 
    - encryption schemes: sg02, bz03
    - signature schemes: bls04, frost, sh00
    - coin schemes: cks05 <br>
   
  and `'group'` is one of \
    'bls12381', 'bn254', 'ed25519', 'rsa512', 'rsa1024', 'rsa2048'. \
  example: `./thetacli keygen 3 5 sg02-bls12381,bz03-ed25519 /path/to/keys/` <br><br>
      

- `enc [pubkey] [infile] [label] [outfile]` \
    encrypt a given infile and store it as outfile \
    `pubkey` = public key of a threshold encryption scheme \
    `infile` = path to file to be encrypted \
    `label` = label for ciphertext \
    `outfile` = path to file to store the encoded ciphertext in
- `verify [pubkey] [msg] [signature]` \
    verify a given signature for a specific message using the specified public key <br>
    `pubkey` = public key of a threshold encryption scheme \
    `msg` = path to message file (bytes) \
    `signature` = path to signature to verify (hex encoded)