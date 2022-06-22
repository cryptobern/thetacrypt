// use std::any::type_name;
use libp2p::{
    floodsub::{Floodsub, FloodsubEvent, FloodsubMessage},
    mdns::{Mdns, MdnsEvent},
    NetworkBehaviour,
    swarm::NetworkBehaviourEventProcess, gossipsub::{GossipsubMessage}
};
use crate::lib::type_of;

pub trait HandleMsg {
    fn handle_msg(&self);
}

// default handling behaviour for a FloodsubMessage
impl HandleMsg for FloodsubMessage {
    fn handle_msg(&self) {
        println!("RECEIVED: {:?} FROM: {:?}", self.data, self.source);
        // println!("data type: {}", type_of(&self.data));
        // println!("From: '{:?}'", self.source);
        // println!("Sequence number: '{:?}'", self.sequence_number);
        // println!("Topic: '{:?}'", self.topics);
    }
}

// default handling behaviour for a GossipsubMessage
impl HandleMsg for GossipsubMessage {
    fn handle_msg(&self) {
        println!("RECEIVED gossipsub msg: '{:?}'", self.data);
        println!("data type: {}", type_of(&self.data));
        println!("From: '{:?}'", self.source);
        println!("Sequence number: '{:?}'", self.sequence_number);
        println!("Topic: '{:?}'", self.topic);
    }
}