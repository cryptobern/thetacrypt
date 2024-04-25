
use std::time::Duration;

use tokio::time;

use futures::{prelude::*, StreamExt};
use libp2p::{
    gossipsub::{Gossipsub, GossipsubEvent, IdentTopic as GossibsubTopic},
    identity,
    swarm::SwarmEvent,
    PeerId, Swarm,
};
use log::{debug, info};

use tokio::sync::mpsc::{Receiver, Sender};

use crate::{config::static_net::{config_service::*, deserialize::Config}, interface::Gossip};
use crate::types::message::*;

use super::net_utils::{self, *};

//T wil be NetMessage
use tonic::async_trait;


//TODO: remove the pub and add a constructor
pub struct P2PComponent {
    pub config: Config,
    pub id: u32,
    pub swarm: Option<Swarm<Gossipsub>>,
    pub topic: GossibsubTopic,
}

#[async_trait]
impl Gossip for P2PComponent
    where Vec<u8>: From<NetMessage> //needed for libp2p
{
    type T = NetMessage;

    fn broadcast(&mut self, net_message: Self::T) {
        
        debug!("NET: Sending a message");
        let swarm = self.swarm.as_mut().unwrap();
        swarm.behaviour_mut().publish(self.topic.clone(), net_message).expect("Publish error");
        
    }

    async fn deliver(&mut self) -> Option<Self::T> {
        // put here the code that handles the swarm and the other cases should go in a different functions that checks the network of peers
        
            tokio::select! {
                
                // polls swarm events
                event = self.swarm.as_mut().unwrap().select_next_some() => match event {
                    // Handles (incoming) Gossipsub-Message
                    SwarmEvent::Behaviour(GossipsubEvent::Message {message, ..}) => {
                        debug!("NET: Received a message");
                        let message: NetMessage = message.data.into();
                        return Some(message);
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        debug!("NET: Listening on {:?}", address);
                        return None
                    }
                    SwarmEvent::Dialing(peer_id) => {
                        debug!("NET: Attempting to dial peer {peer_id}");
                        return None
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, num_established: _, concurrent_dial_errors: _} => {
                        debug!("NET: Successfully established connection to peer {peer_id} on {}", endpoint.get_remote_address());
                        return None
                    },
                    SwarmEvent::ConnectionClosed { peer_id, endpoint, num_established: _, cause } => {
                        debug!("NET: Closed connection to peer {peer_id} on {} due to {:?}", endpoint.get_remote_address(), cause);
                        return None
                    }
                    _ => {return None}
                }
    }
  
}
}

impl P2PComponent {

    async fn monitor_network(&mut self) {
        let mut list_peers_timer = time::interval(Duration::from_secs(60));
        let swarm = self.swarm.as_mut().unwrap();
        tokio::select! {
            // Periodically list all our known peers.
            _tick = list_peers_timer.tick() => {
                debug!("NET: My currently known peers: ");
                for (peer, _) in swarm.behaviour().all_peers() {
                    debug!("- {}", peer);
                }

                debug!("NET: My currently connected mesh peers: ");
                for peer in swarm.behaviour().all_mesh_peers() {
                    debug!("- {}", peer);
                }
            }    
        }
        
    }

    pub fn new(config: Config, id: u32) -> Self{
        let topic: GossibsubTopic = GossibsubTopic::new("gossipsub broadcast");
        return P2PComponent{
            config: config,
            id: id,
            swarm: None,
            topic: topic,
        }
    }
    
    ///init() for now provides the initialization of libp2p
    //TODO: The goal will be to setup the different modules available for transmission 
    pub async fn init(&mut self){ //Handle an error that in case doesn't allow the component to exist if it is not possible to instantiate the swarm
        // Create a Gossipsub topic

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
       let mut swarm = create_gossipsub_swarm(&self.topic, id_keys.clone(), transport, local_peer_id);
       self.swarm = Some(swarm);

       // load listener address from config file
       let listen_addr = get_p2p_listen_addr(&self.config, self.id);
       debug!("NET: Listening for P2P on: {}", listen_addr);

       // bind port to listener address
       let swarm = self.swarm.as_mut().unwrap();
       match swarm.listen_on(listen_addr.clone()) {
           Ok(_) => (),
           Err(error) => debug!("NET: listen {:?} failed: {:?}", listen_addr, error),
       }
        
       self.dial_local_net().await
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
            let swarm = self.swarm.as_mut().unwrap();
            match swarm.dial(dial_addr.clone()) {
                Ok(_) => {}
                Err(e) => debug!("NET: Dial {:?} failed: {:?}", dial_addr, e),
            };
        }

        debug!("NET: Waiting for connection to first peer");
        // Now we wait until we've successfully connected to at least one peer.
        let swarm = self.swarm.as_mut().unwrap();
        loop {
            match swarm.select_next_some().await {
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
        incoming_msg_sender: Sender<NetMessage>,
    ) -> ! {
        
        loop {
            // tokio::select! {
                // // Periodically list all our known peers.
                // _tick = list_peers_timer.tick() => {
                //     debug!("NET: My currently known peers: ");
                //     for (peer, _) in swarm.behaviour().all_peers() {
                //         debug!("- {}", peer);
                //     }

                //     debug!("NET: My currently connected mesh peers: ");
                //     for peer in swarm.behaviour().all_mesh_peers() {
                //         debug!("- {}", peer);
                //     }
                // }
                // // polls swarm events
                // event = swarm.select_next_some() => match event {
                //     // Handles (incoming) Gossipsub-Message
                //     SwarmEvent::Behaviour(GossipsubEvent::Message {message, ..}) => {
                //         debug!("NET: Received a message");
                //         incoming_msg_sender.send(message.data.into()).await.unwrap();
                //     }
                //     SwarmEvent::NewListenAddr { address, .. } => {
                //         debug!("NET: Listening on {:?}", address);
                //     }
                //     SwarmEvent::Dialing(peer_id) => {
                //         debug!("NET: Attempting to dial peer {peer_id}");
                //     }
                //     SwarmEvent::ConnectionEstablished { peer_id, endpoint, num_established: _, concurrent_dial_errors: _} => {
                //         debug!("NET: Successfully established connection to peer {peer_id} on {}", endpoint.get_remote_address());
                //     },
                //     SwarmEvent::ConnectionClosed { peer_id, endpoint, num_established: _, cause } => {
                //         debug!("NET: Closed connection to peer {peer_id} on {} due to {:?}", endpoint.get_remote_address(), cause);
                //     }
                //     _ => {}
                // }
            // }
        }
    }
}


