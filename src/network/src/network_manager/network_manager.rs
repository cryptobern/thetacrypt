use log::info;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::{config::static_net::deserialize::Config, interface::{Gossip, TOB}};

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

impl<NetMessage, G: Gossip<NetMessage>> NetworkManager<NetMessage,G> {
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

    pub async fn run(&mut self){
        loop{
            tokio::select! {
                protocol_msg = self.outgoing_msg_receiver.recv() => {
                    //check condition for the channel (does it need gossip, tob, additional PtP)
                    info!("Received message from protocol layer");
                    let _ = self.gossip_channel.broadcast(protocol_msg.unwrap());
                    info!("... sending to the network");
                },
                gossip_msg = self.gossip_channel.deliver() => {
                    if let Some(message) = gossip_msg {
                        info!("Received message from network");
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