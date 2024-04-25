use log::info;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::{config::static_net::deserialize::Config, interface::{Gossip, TOB}};
use crate::types::message::{NetMessage, NetMessageMetadata, Channel};

// T is the generic for the message
// G is the generic for the Gossip module
// P is the generic for Total order broadcast
pub struct NetworkManager{
    outgoing_msg_receiver: Receiver<NetMessage>,
    incoming_msg_sender: Sender<NetMessage>,
    config: Config, //TODO: to review this Config, also the position
    my_id: u32,
    gossip_channel: Box<dyn Gossip<T= NetMessage>>,
    tob_channel: Option<Box<dyn TOB<T= NetMessage>>>,
}


impl NetworkManager{
    pub fn new(    
        outgoing_msg_receiver: Receiver<NetMessage>,
        incoming_msg_sender: Sender<NetMessage>,
        config: Config,
        my_id: u32,
        gossip_channel: Box<dyn Gossip<T= NetMessage>>,
        tob_channel: Option<Box<dyn TOB<T= NetMessage>>>
    ) -> Self{
            return NetworkManager{
                outgoing_msg_receiver: outgoing_msg_receiver,
                incoming_msg_sender: incoming_msg_sender,
                config: config,
                my_id: my_id,
                gossip_channel: gossip_channel,
                tob_channel: None,
            };
    }
    
    //Here should go all the logic of the network layer    
    pub async fn run(&mut self){

        let tob_ref = self.tob_channel.as_ref();
        loop{
            tokio::select! {
                Some(protocol_msg) = self.outgoing_msg_receiver.recv() => { //if the channel closes, then the recv() returns None and the branch is ignored
                    //check condition for the channel (does it need gossip, tob, additional PtP)
                    let net_message = protocol_msg.clone();
                    let channel = net_message.get_metadata().get_channel();
                    match channel {
                        Channel::Gossip => info!("Gossip channel"),
                        Channel::TOB => info!("TOB channel"),
                        Channel::PointToPoint{receiver_id} => info!("Point to Point channel"), //here handle authentication   
                    };
                    info!("Received message from protocol layer");
                    let _ = self.gossip_channel.broadcast(net_message.clone());
                    info!("... sending to the network");

                    // The next line implements the logic to give back to the protocol a message produced locally 
                    // so that a self-message appears in teh received ones. 
                    // It is up to the implementers of a certain protocol the decision of handling 
                    // a locally produced message already in the protocol to optimize in terms of transmission
                    // latency and verification time. 
                    let _ = self.incoming_msg_sender.send(net_message).await;
                    info!("... forwarding my message back to the protocol");
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
                },
                // Some(tob_msg) = tob_ref.unwrap().deliver(), if !tob_ref.is_none() => {//after the comma we have a precondition to enable the branch
                //     todo!()
                // },
                else => { break },
                
                // tob_message = self.tob_channel.as_ref().unwrap().deliver() => { //TODO: dangerous unwarp(), to handle
                //     todo!()
                // }
            }
        }
    }
}