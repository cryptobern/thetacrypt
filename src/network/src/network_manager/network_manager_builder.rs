use tokio::sync::mpsc::{Receiver, Sender};
use crate::{interface::{Gossip, TOB}, types::{config::NetworkConfig, message::NetMessage}};

use super::network_manager::NetworkManager;

#[derive(Default)]
pub struct NetworkManagerBuilder{
    outgoing_msg_receiver: Option<Receiver<NetMessage>>,
    incoming_msg_sender: Option<Sender<NetMessage>>,
    config: Option<NetworkConfig>, //TODO: to review this Config, also the position
    my_id: u32,
    gossip_channel: Option<Box<dyn Gossip<T= NetMessage>>>,
    tob_channel: Option<Box<dyn TOB<T= NetMessage>>>,
}

impl NetworkManagerBuilder{

    pub fn set_outgoing_msg_receiver(&mut self, receiver: Receiver<NetMessage>) {
        self.outgoing_msg_receiver = Some(receiver)
    }

    pub fn set_incoming_message_sender(&mut self, sender: Sender<NetMessage>){
        self.incoming_msg_sender = Some(sender)
    }

    pub fn set_config(&mut self, config: NetworkConfig){
        self.config = Some(config)
    }

    pub fn set_id(&mut self, id: u32){
        self.my_id = id
    }

    pub fn set_gossip_channel(&mut self, gossip_channel: Box<dyn Gossip<T= NetMessage>>){
        self.gossip_channel = Some(gossip_channel)
    }

    pub fn set_tob_channel(&mut self, tob_channel: Box<dyn TOB<T= NetMessage>>){
        self.tob_channel = Some(tob_channel)
    }

    pub fn build(self) -> NetworkManager{
        return NetworkManager::new(
            self.outgoing_msg_receiver.expect("Set Receiver for NetworkManager"),
            self.incoming_msg_sender.expect("Set Sender for NetworkManager"),
            self.config.expect("Set config for NetworkManager"),
            self.my_id,
            self.gossip_channel.expect("Set gossip channel for NetworkManager"),
            self.tob_channel
        )
    }

}