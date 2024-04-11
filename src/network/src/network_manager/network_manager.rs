use log::info;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::{config::static_net::deserialize::Config, interface::{Gossip, TOB}};
use crate::types::message::{NetMessage, NetMessageMetadata, Channel};

// T is the generic for the message
// G is the generic for the Gossip module
// P is the generic for Total order broadcast
pub struct NetworkManager<T, G: Gossip<T>> {//, P: TOB<T> > {
    outgoing_msg_receiver: Receiver<T>,
    incoming_msg_sender: Sender<T>,
    config: Config, //TODO: to review this Config, also the position
    my_id: u32,
    gossip_channel: G,
    // tob_channel: Option<P>,
}

impl<G: Gossip<NetMessage>> NetworkManager<NetMessage,G> {
    pub fn new(    
        outgoing_msg_receiver: Receiver<NetMessage>,
        incoming_msg_sender: Sender<NetMessage>,
        config: Config,
        my_id: u32,
        gossip_channel: G,
        // tob_channel: Option<P>
    ) -> Self{
            return NetworkManager{
                outgoing_msg_receiver: outgoing_msg_receiver,
                incoming_msg_sender: incoming_msg_sender,
                config: config,
                my_id: my_id,
                gossip_channel: gossip_channel,
                // tob_channel: None,
            };
        }

    //Here should go all the logic of the network layer    
    pub async fn run(&mut self){
        loop{
            tokio::select! {
                protocol_msg = self.outgoing_msg_receiver.recv() => {
                    //check condition for the channel (does it need gossip, tob, additional PtP)
                    let net_message = protocol_msg.unwrap().clone();
                    let channel = net_message.get_metadata().get_channel();
                    match channel {
                        Channel::Gossip => info!("Gossip channel"),
                        Channel::TOB => info!("TOB channel"),
                        Channel::PointToPoint{receiver_id} => info!("Point to Point channel"), //here handle authentication   
                    };
                    info!("Received message from protocol layer");
                    let _ = self.gossip_channel.broadcast(net_message);
                    info!("... sending to the network");
                },
                gossip_msg = self.gossip_channel.deliver() => {
                    if let Some(message) = gossip_msg {
                        let net_message = message.clone();
                        info!("Received message from network");
                        let channel = net_message.get_metadata().get_channel();
                        match channel {
                            Channel::Gossip => {info!("Gossip channel")},
                            Channel::TOB => todo!(),
                            Channel::PointToPoint{receiver_id} => {
                                //check the receiver id and encrypt accordingly before broadcasting on gossip
                                if receiver_id.contains(&self.my_id) {
                                    info!("My id is in the receivers");
                                }else{
                                    info!("My id is NOT in the receivers");
                                    continue;
                                }
                            },   
                        };
                        
                        let _ = self.incoming_msg_sender.send(message).await; //we need to wait here in casy the channel is full, we might add handling error if the channel closes
                        info!("... forwarding to the protocol");
                    }
                    // let message = gossip_msg.unwrap(); //handle a secure unwrap
                    
                },
                // tob_message = self.tob_channel.as_ref().unwrap().deliver() => { //TODO: dangerous unwarp(), to handle
                //     todo!()
                // }
            }
        }
    }

}