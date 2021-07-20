# Notion of a party
In this document, we compare approaches from different consensus implementations on how to define the notion of a party. 

## HotStuff
**ReplicaID**: `uint16_t`; high-level id used in consensus to identify proposer/voter<br>
**PeerID**: `uint256_t`; 256 bit hash of a NetAddr or X509 certificate, used to send messages (network layer)<br>
**NetAddr**: consists of a uint32_t ip, uint16_t port

# Tendermint
Reference: https://github.com/tendermint/tendermint/blob/master/docs/architecture/adr-062-p2p-architecture.md 
 
**NodeID**: `string`; hex-encoded crypto.Address lowercase and of length 40 

Each Node has one or more NodeAdress addresses that it can be reached at 
**PeerID** of type **NodeID** used for identification 

Types of nodes:  
- Full node: Stores the entire state of a blockchain. 
- Seed node: Provides a node with a list of peers which a node can connect to 
- Sentry node: Similar to a full node, but has one or more private peers. These peers may be validators or other full nodes in the network 
- Validators: Participate in the security of a network.  

# Diem
https://github.com/diem/diem/issues/3960 

**AcountAddress**: `[u8, 16]`; derived from identity public key (x25519 key, last 16 bytes) <br>
**PeerID** alias **AccountAddress** (move-core/types/src/account_address.rs), used to send messages<br> 
**Author** alias **AccountAddress**, used for consensus to identify voter/proposer
For consensus, a new struct **Author** is used, which is an alias for **AccountAddress** 
