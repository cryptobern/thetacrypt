use libp2p::{
    floodsub::{Floodsub, FloodsubEvent, FloodsubMessage},
    mdns::{Mdns, MdnsEvent},
    NetworkBehaviour,
    swarm::NetworkBehaviourEventProcess, gossipsub::{GossipsubEvent, Gossipsub, GossipsubMessage, MessageId}, PeerId,
};

#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
pub struct MyBehaviour {
    pub floodsub: Floodsub,
    pub mdns: Mdns, // automatically discovers other libp2p nodes on the local network.
}

#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
pub struct GossipBehaviour {
    pub gossipsub: Gossipsub,
}

pub trait HandleShare {
    fn handle_share(&self);
}

// default behaviour for HandleShare is to print the received data and the sender (peerID)
impl HandleShare for FloodsubMessage {
    fn handle_share(&self) {
        println!("Received: '{:?}' from {:?}", self.data, self.source);
    }
}

impl HandleShare for GossipsubMessage {
    fn handle_share(&self) {
        println!("Received gossipsub message: '{:?}' from {:?}", self.data, self.source);
    }
}

pub fn handle_gossip_msg(peer_id: PeerId, message_id: MessageId, message: GossipsubMessage) {
    println!("Received gossipsub message: '{:?}'", message.data);
    println!("With: {:?}", message_id);
    println!("From: {:?}", peer_id);
}

impl NetworkBehaviourEventProcess<FloodsubEvent> for MyBehaviour {
    // Called when `floodsub` produces an event.
    fn inject_event(&mut self, message: FloodsubEvent) {
        if let FloodsubEvent::Message(message) = message {
            message.handle_share();
        }
    }
}

impl NetworkBehaviourEventProcess<MdnsEvent> for MyBehaviour {
    // Called when `mdns` produces an event.
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(list) => {
                for (peer, _) in list {
                    self.floodsub.add_node_to_partial_view(peer);
                }
            }
            MdnsEvent::Expired(list) => {
                for (peer, _) in list {
                    if !self.mdns.has_node(&peer) {
                        self.floodsub.remove_node_from_partial_view(&peer);
                    }
                }
            }
        }
    }
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for GossipBehaviour {
    // Called when `gossipsub` produces an event.
    fn inject_event(&mut self, message: GossipsubEvent) {
        if let GossipsubEvent::Message {
            propagation_source: peer_id,
            message_id: id,
            message} = message {
            // message.handle_share();
            // handle_gossip_msg();
        }
    }
}