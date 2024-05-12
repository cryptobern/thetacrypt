# Network Node

A network node encapsulates the information needed for the replica connectivity towards other nodes running Thetacrypt.

Because Thetacrypt implements two different configurations, the network node needs to distinguish between the case it needs
a proxy node to simply delegate networking operation, or when it needs to know other peers because it is part of a peer-to-peer
group.

The `NetworkConfig` aims at specifying the details of the local node, and the information needed for the communication with
other nodes.

```
pub struct NetworkConfig {
    pub local_peer: NetworkPeer,
    pub peers: Option<Vec<NetworkPeer>>,
    pub proxy: Option<NetworkProxy>,
    pub base_listen_address: String,
}
```

Somewhere we also need to store the number of total nodes assumed in the network.

N.B.: if we are working with the proxy we cannot count on knowing all the peers
