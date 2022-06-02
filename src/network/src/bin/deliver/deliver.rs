// use std::any::type_name;
use libp2p::{
    floodsub::{Floodsub, FloodsubEvent, FloodsubMessage},
    mdns::{Mdns, MdnsEvent},
    NetworkBehaviour,
    swarm::NetworkBehaviourEventProcess, gossipsub::{GossipsubMessage, MessageId}, PeerId,
};
use network::lib::type_of;

#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
pub struct MyBehaviour {
    pub floodsub: Floodsub,
    pub mdns: Mdns, // automatically discovers other libp2p nodes on the local network.
}

pub trait HandleMsg {
    fn handle_share(&self);
}

// default behaviour for HandleMsg: print received data and sender (peerID)
impl HandleMsg for FloodsubMessage {
    fn handle_share(&self) {
        println!("Received: '{:?}' from {:?}", self.data, self.source);
    }
}

impl HandleMsg for GossipsubMessage {
    fn handle_share(&self) {
        println!("Gossipsub msg: '{:?}'", self.data);
        println!("type of msg: {}", type_of(&self.data));
        println!("From: '{:?}'", self.source);
        println!("Sequence number: '{:?}'", self.sequence_number);
        println!("Topic: '{:?}'", self.topic);
    }
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