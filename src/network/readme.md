# Network layer

The network layer aims at abstracting the communication from the rest of the codebase, providing precise interfaces.

The entrypoint is the network manager, which takes care of orchestrating the processing of the incoming and outgoing messages.
It also represents the connecting module with the protocol logic.

The network manager exposes the interfaces of two main modules: one for peer-to-peer communication, which in the code base is referred to as a `Gossip` interface, and a total order broadcast module which is abbreviated with `TOB` for the interface name.

In the case of the network layer too, the modular design allows for flexible integration of different communication solutions.

The first entails the implementation of an ad-hoc networking layer realized through `libp2p`. `P2PComponent` under `p2p` in this code.

The second considers integrating general proxy interfaces to delegate the networking functionality to an external platform. Under `proxy` in this code.
