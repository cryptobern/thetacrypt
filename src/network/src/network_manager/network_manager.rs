use std::sync::Arc;

use log::{error, info, warn};
use tokio::sync::{mpsc::{Receiver, Sender}, Notify};

use crate::{interface::{Gossip, TOB}, types::config::NetworkConfig};
use crate::types::message::{NetMessage, Channel};

// T is the generic for the message
// G is the generic for the Gossip module
// P is the generic for Total order broadcast
pub struct NetworkManager{
    outgoing_msg_receiver: Receiver<NetMessage>,
    incoming_msg_sender: Sender<NetMessage>,
    config: NetworkConfig, //TODO: to review this Config, also the position
    my_id: u32,
    gossip_channel: Box<dyn Gossip<T= NetMessage>>,
    tob_channel: Option<Box<dyn TOB<T= NetMessage>>>,
}


impl NetworkManager{
    pub fn new(    
        outgoing_msg_receiver: Receiver<NetMessage>,
        incoming_msg_sender: Sender<NetMessage>,
        config: NetworkConfig,
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
    pub async fn run(&mut self, shutdown_notify: Arc<Notify>) -> Result<(), String> {

        let init_result = self.gossip_channel.init().await;

        if init_result.is_err(){
            let error = format!("Error initializing the network layer: {}", init_result.err().unwrap());
            error!("{}", error);
            return Err(error);
        }

        let tob_ref = self.tob_channel.as_ref();
        loop{
            tokio::select! {
                protocol_msg = self.outgoing_msg_receiver.recv() => { //if the channel closes, then the recv() returns None and the branch is ignored
                    //check condition for the channel (does it need gossip, tob, additional PtP)
                    match protocol_msg {
                        Some(net_message) => {
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
                            let result = self.incoming_msg_sender.send(net_message).await;
                            match result {
                                Ok(_) => info!("... forwarding my message back to the protocol"),
                                Err(e) => error!("Send error occurred: {}", e),
                            }
                        },
                        None => {
                            warn!("The protocol layer has closed the channel");
                            return Err("The protocol layer has closed the channel".to_string());
                        }
                    }
                },
                gossip_msg = self.gossip_channel.deliver() => { //is the branch disabled if I used Some()? Yes, the pattern matching fails for this branch, but the select
                                                                //waits on the other branches until one produces something or all of them become disabled.
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
                    }else{
                        warn!("The gossip channel has closed");
                        return Err("The gossip channel has closed".to_string());
                    }
                },
                    // Some(tob_msg) = tob_ref.unwrap().deliver(), if !tob_ref.is_none() => {//after the comma we have a precondition to enable the branch
                    //     todo!()
                    // },
                _ = shutdown_notify.notified() => {
                    info!("Shutting down the network layer");
                    return Ok(());
                }
                
                // tob_message = self.tob_channel.as_ref().unwrap().deliver() => { //TODO: dangerous unwarp(), to handle
                //     todo!()
                // }
            }
        }
    }
}