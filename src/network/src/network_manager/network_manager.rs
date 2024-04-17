use log::info;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::{config::static_net::deserialize::Config, interface::{Gossip, TOB}};
use crate::types::message::{NetMessage, NetMessageMetadata, Channel};

// T is the generic for the message
// G is the generic for the Gossip module
// P is the generic for Total order broadcast
pub struct NetworkManager<T, G: Gossip<T>, P: TOB<T> > {
    outgoing_msg_receiver: Receiver<T>,
    incoming_msg_sender: Sender<T>,
    config: Config, //TODO: to review this Config, also the position
    my_id: u32,
    gossip_channel: G,
    tob_channel: Option<P>,
}

impl<G: Gossip<NetMessage>, P: TOB<NetMessage>> NetworkManager<NetMessage,G, P> {
    pub fn new(    
        outgoing_msg_receiver: Receiver<NetMessage>,
        incoming_msg_sender: Sender<NetMessage>,
        config: Config,
        my_id: u32,
        gossip_channel: G,
        tob_channel: Option<P>
    ) -> Self{
            return NetworkManager{
                outgoing_msg_receiver: outgoing_msg_receiver,
                incoming_msg_sender: incoming_msg_sender,
                config: config,
                my_id: my_id,
                gossip_channel: gossip_channel,
                tob_channel: tob_channel,
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
                    let _ = self.gossip_channel.broadcast(net_message);
                    info!("... sending to the network");

                    let _ = self.incoming_msg_sender.send(protocol_msg).await; 
                        info!("... forwarding my message back to the protocol");

                },
                Some(gossip_msg) = self.gossip_channel.deliver() => {
                    
                        let net_message = gossip_msg.clone();
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
                        
                        let _ = self.incoming_msg_sender.send(gossip_msg).await; //we need to wait here in casy the channel is full, we might add handling error if the channel closes
                        info!("... forwarding to the protocol");   
                },
                Some(tob_msg) = tob_ref.unwrap().deliver(), if !tob_ref.is_none() => {//after the comma we have a precondition to enable the branch
                    todo!()
                },
                else => { break },
                
                // tob_message = self.tob_channel.as_ref().unwrap().deliver() => { //TODO: dangerous unwarp(), to handle
                //     todo!()
                // }
            }
        }
    }

}