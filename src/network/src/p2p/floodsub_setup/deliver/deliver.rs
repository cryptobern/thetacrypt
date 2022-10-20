use libp2p::floodsub::FloodsubMessage;
// use crate::lib::type_of;

pub trait HandleMsg {
    fn handle_msg(&self);
}

// default implementation for handling an incoming FloodsubMessage
impl HandleMsg for FloodsubMessage {
    fn handle_msg(&self) {
        println!("RECEIVED: {:?} FROM: {:?}", self.data, self.source);
        // println!("data type: {}", type_of(&self.data));
        // println!("From: '{:?}'", self.source);
        // println!("Sequence number: '{:?}'", self.sequence_number);
        // println!("Topic: '{:?}'", self.topics);
    }
}