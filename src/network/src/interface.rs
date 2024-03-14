use futures::Future;
use tokio::sync::mpsc::{Receiver, Sender};

//T wil be NetMessage
use tonic::async_trait;

use crate::{config::static_net::deserialize::Config, types::message::NetMessage};

// #[async_trait]
pub trait Gossip<T, F:Future> {

    fn broadcast(&mut self, message: T);
    fn deliver(&mut self) -> F;
}

#[async_trait]
pub trait TOB<T>{
    fn broadcast(message: T);
    async fn deliver(&self) -> Option<T>;
}


// T is the generic for the message
// G is the generic for the Gossip module
// P is the generic for Total order broadcast
pub struct NetworkManager<T, F: Future, G: Gossip<T, F>, P: TOB<T>> {
    outgoing_msg_receiver: Receiver<T>,
    incoming_msg_sender: Sender<T>,
    config: Config, //TODO: to review this Config, also the position
    my_id: u32,
    gossip_channel: G,
    tob_channel: Option<P>,
}

// impl<T, G: Gossip<T>, P: TOB<T>> NetworkManager<T,G,P> {
//     pub fn new(    
//         outgoing_msg_receiver: Receiver<T>,
//         incoming_msg_sender: Sender<T>,
//         config: Config,
//         my_id: u32,
//         gossip_channel: G,
//         tob_channel: Option<P>) -> Self{
//             return NetworkManager{
//                 outgoing_msg_receiver: outgoing_msg_receiver,
//                 incoming_msg_sender: incoming_msg_sender,
//                 config: config,
//                 my_id: my_id,
//                 gossip_channel: gossip_channel,
//                 tob_channel: tob_channel,
//             };
//         }

//         async fn run(&mut self){
//             loop{
//                 tokio::select! {
//                     protocol_msg = self.outgoing_msg_receiver.recv() => {
//                         //check condition for the channel 
//                         //only gosssip
//                         let _ = self.gossip_channel.broadcast(protocol_msg.unwrap());
//                     },
//                     gossip_msg = self.gossip_channel.deliver() => {
//                         let message = gossip_msg;
//                         let _ = self.incoming_msg_sender.send(message);
//                     },
//                     tob_message = self.tob_channel.as_ref().unwrap().deliver() => { //TODO: dangerous unwarp(), to handle
//                         todo!()
//                     }
//                 }
//             }
//         }

//     }