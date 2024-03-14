
use std::time::Duration;

use async_std::stream::Pending;
use tokio::time;

use futures::{prelude::*, StreamExt};
use libp2p::{
    gossipsub::{Gossipsub, GossipsubEvent, IdentTopic as GossibsubTopic},
    identity,
    swarm::SwarmEvent,
    PeerId, Swarm,
};
use log::{debug, info};

use futures::task::Poll;

use tokio::sync::mpsc::{Receiver, Sender};
use trust_dns_resolver::proto::op::message;

use crate::{config::static_net::{config_service::*, deserialize::Config}, interface::Gossip};
use crate::types::message::*;

use super::net_utils::{self, *};

//T wil be NetMessage
use tonic::async_trait;


//TODO: remove the pub and add a constructor
pub struct P2PComponent<NetMessage> {
    pub config: Config,
    pub id: u32,
    pub swarm: Swarm<Gossipsub>,
    pub topic: GossibsubTopic,
    pub receiver: Receiver<NetMessage>
}

struct NetFuture<T> {
    message: Option<T>,
}

impl<T> NetFuture<T> {
    pub fn new() -> Self{
        return NetFuture { message: None }
    }
}
impl<T> Future for NetFuture<T> {
    type Output = Option<T>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        todo!()
        // let event = self.swarm.select_next_some().await;
        
        // match event {
        //     // Handles (incoming) Gossipsub-Message
        //     SwarmEvent::Behaviour(GossipsubEvent::Message {message, ..}) => {
        //         debug!("NET: Received a message");
        //         return message.data.into()
        //     },
        //     _ => {return Poll::Pending}
        // }
    }
}

#[async_trait]
impl Gossip<NetMessage, NetFuture<NetMessage>> for P2PComponent<NetMessage> 
    where Vec<u8>: From<NetMessage> //needed for libp2p
{

    fn broadcast(&mut self, net_message: NetMessage) {
        
        debug!("NET: Sending a message");
        self.swarm.behaviour_mut().publish(self.topic.clone(), net_message).expect("Publish error");
        
    }

    fn deliver(&mut self) -> NetFuture<NetMessage> {

        //create the future 
        let future = NetFuture::new();
        return future
    }
  
}

impl P2PComponent<NetMessage> {
    
    ///init() for now provides the initialization of libp2p
    //TODO: The goal will be to setup the different modules available for transmission 
    fn init(&mut self){
        // Create a Gossipsub topic
       let topic: GossibsubTopic = GossibsubTopic::new("gossipsub broadcast");

       // Create a random Keypair and PeerId (hash of the public key)
       let id_keys = identity::Keypair::generate_ed25519();
       let local_peer_id = PeerId::from(id_keys.public());
       // println!(">> NET: Local peer id: {:?}", local_peer_id);

       // Create a keypair for authenticated encryption of the transport.
       let noise_keys = create_noise_keys(&id_keys);

       // Create a tokio-based TCP transport, use noise for authenticated
       // encryption and Mplex for multiplexing of substreams on a TCP stream.
       let transport = create_tcp_transport(noise_keys);

       // Create a Swarm to manage peers and events.
       self.swarm = create_gossipsub_swarm(&topic, id_keys.clone(), transport, local_peer_id);

       // load listener address from config file
       let listen_addr = get_p2p_listen_addr(&self.config, self.id);
       debug!("NET: Listening for P2P on: {}", listen_addr);

       // bind port to listener address
       match self.swarm.listen_on(listen_addr.clone()) {
           Ok(_) => (),
           Err(error) => debug!("NET: listen {:?} failed: {:?}", listen_addr, error),
       }
    }

    /// Dial all peers, and wait for at least one connection to be established.
    ///
    /// Dialing all peers will let the underlying gossipsub network know of their existence, thus
    /// allowing it to build up its mesh network.
    async fn dial_local_net(&mut self) {
        // Start by dialing all peers other than ourselves, letting the underlying network layer know
        // of their existenec, allowing it to connect if required.
        for peer_id in &self.config.ids {
            if *peer_id == self.id {
                // Let's not dial ourselves.
                continue;
            }

            let dial_addr = get_dial_addr(&self.config, *peer_id);
            // Note that the dial() method will *not* erorr if connection fails - e.g. dialing a
            // not-yet-reachable peer will work just fine. I assume it will rather fail if the thing we
            // pass is not actually dial-able - e.g. an invalid IP, or a peer ID of a peer we do not
            // know of.
            // As such, .dial() seems to just be a way to let the network layer know of peers which
            // exist, so it can try to connect to them.
            match self.swarm.dial(dial_addr.clone()) {
                Ok(_) => {}
                Err(e) => debug!("NET: Dial {:?} failed: {:?}", dial_addr, e),
            };
        }

        debug!("NET: Waiting for connection to first peer");
        // Now we wait until we've successfully connected to at least one peer.
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::ConnectionEstablished { endpoint, .. } => {
                    debug!(
                        "NET: Successfully connected to first peer on: {:?}",
                        endpoint.get_remote_address()
                    );
                    info!("NET: Ready for client requests...");
                    break;
                }
                _ => {}
            }
        }
    }

    // kick off tokio::select event loop to handle events
pub async fn run_event_loop(&mut self,
    topic: GossibsubTopic,
    mut outgoing_msg_receiver: Receiver<NetMessage>,
    incoming_msg_sender: Sender<NetMessage>,
) -> ! {
    let mut list_peers_timer = time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            // Periodically list all our known peers.
            _tick = list_peers_timer.tick() => {
                debug!("NET: My currently known peers: ");
                for (peer, _) in self.swarm.behaviour().all_peers() {
                    debug!("- {}", peer);
                }

                debug!("NET: My currently connected mesh peers: ");
                for peer in self.swarm.behaviour().all_mesh_peers() {
                    debug!("- {}", peer);
                }
            }
            // polls swarm events
            event = self.swarm.select_next_some() => match event {
                // Handles (incoming) Gossipsub-Message
                SwarmEvent::Behaviour(GossipsubEvent::Message {message, ..}) => {
                    debug!("NET: Received a message");
                    incoming_msg_sender.send(message.data.into()).await.unwrap();
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    debug!("NET: Listening on {:?}", address);
                }
                SwarmEvent::Dialing(peer_id) => {
                    debug!("NET: Attempting to dial peer {peer_id}");
                }
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, num_established: _, concurrent_dial_errors: _} => {
                    debug!("NET: Successfully established connection to peer {peer_id} on {}", endpoint.get_remote_address());
                },
                SwarmEvent::ConnectionClosed { peer_id, endpoint, num_established: _, cause } => {
                    debug!("NET: Closed connection to peer {peer_id} on {} due to {:?}", endpoint.get_remote_address(), cause);
                }
                _ => {}
            }
        }
    }
}


}


