
use std::time::Duration;

use tokio::time;

use futures::StreamExt;
use libp2p::{
    gossipsub::{Gossipsub, GossipsubEvent, IdentTopic as GossibsubTopic},
    identity,
    swarm::SwarmEvent,
    PeerId, Swarm,
};
use log::{debug, error, info};

use crate::{interface::Gossip, types::config::NetworkConfig};
use crate::types::message::*;


//T wil be NetMessage
use tonic::async_trait;


//TODO: remove the pub and add a constructor
pub struct P2PComponent {
    config: NetworkConfig,
    swarm: Option<Swarm<Gossipsub>>,
    topic: GossibsubTopic,
}

#[async_trait]
impl Gossip for P2PComponent
    where Vec<u8>: From<NetMessage> //needed for libp2p
{
    type T = NetMessage;

    fn broadcast(&mut self, net_message: Self::T) -> Result<(), String> {
        
        debug!("NET: Sending a message");
        if let Some(swarm) = self.swarm.as_mut(){
            let _ = swarm.behaviour_mut()
                        .publish(self.topic.clone(), net_message)
                        .map_err(|e| {
                            error!("NET: Failed to publish message: {:?}", e);
                            return ((),"failed to publish message".to_string())
                        });
            Ok(())
        }else{
            error!("NET: Failed to publish message: No swarm available");
            return Err("Failed to publish message: No swarm available".to_string())
        }
    }

    async fn deliver(&mut self) -> Option<Self::T> {
        // put here the code that handles the swarm and the other cases should go in a different functions that checks the network of peers
        
           loop {
                // TODO: add a timeout to avoid waiting forever? 
                // do we need to handle the case of a timeout?
                // polls swarm events
                let event = self.swarm.as_mut().unwrap().select_next_some().await;
                match event {
                    // Handles (incoming) Gossipsub-Message
                    SwarmEvent::Behaviour(GossipsubEvent::Message {message, ..}) => {
                        debug!("NET: Received a message");
                        let message: NetMessage = message.data.into();
                        return Some(message);
                    }
                    // SwarmEvent::NewListenAddr { address, .. } => {
                    //     debug!("NET: Listening on {:?}", address);
                    //     return None
                    // }
                    // SwarmEvent::Dialing(peer_id) => {
                    //     debug!("NET: Attempting to dial peer {peer_id}");
                    //     return None
                    // }
                    // SwarmEvent::ConnectionEstablished { peer_id, endpoint, num_established: _, concurrent_dial_errors: _} => {
                    //     debug!("NET: Successfully established connection to peer {peer_id} on {}", endpoint.get_remote_address());
                    //     return None
                    // },
                    // SwarmEvent::ConnectionClosed { peer_id, endpoint, num_established: _, cause } => {
                    //     // TODO: handle the case of reconnection ?
                    //     debug!("NET: Closed connection to peer {peer_id} on {} due to {:?}", endpoint.get_remote_address(), cause);
                    //     return None
                    // }
                    _ => {}
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

    // TODO: apply get swarm
    pub fn get_swarm(&mut self) -> Result<&mut Swarm<Gossipsub>, String> {
        self.swarm.as_mut().ok_or_else(|| "Swarm not initialized".to_string())
    }

    pub fn new(config: NetworkConfig, id: u32) -> Self{
        let topic: GossibsubTopic = GossibsubTopic::new("gossipsub broadcast");
        return P2PComponent{
            config: config,
            swarm: None,
            topic: topic,
        }
    }
    
    ///init() for now provides the initialization of libp2p
    //TODO: The goal will be to setup the different modules available for transmission 
    pub async fn init(&mut self) -> Result<(), String> { 
        // Create a Gossipsub topic

       // Create a random Keypair and PeerId (hash of the public key)
       let id_keys = identity::Keypair::generate_ed25519();
       let local_peer_id = PeerId::from(id_keys.public());
       // println!(">> NET: Local peer id: {:?}", local_peer_id);

       // Create a keypair for authenticated encryption of the transport.
       let noise_keys = utils::create_noise_keys(&id_keys);

       // Create a tokio-based TCP transport, use noise for authenticated
       // encryption and Mplex for multiplexing of substreams on a TCP stream.
       let transport = utils::create_tcp_transport(noise_keys);

       // Create a Swarm to manage peers and events.
       let swarm = utils::create_gossipsub_swarm(&self.topic, id_keys.clone(), transport, local_peer_id);
       self.swarm = Some(swarm);

       // load listener address from config file
       let listen_addr = self.config.get_p2p_listen_addr();
       debug!("NET: Listening for P2P on: {}", listen_addr);

       // bind port to listener address
       let swarm = self.swarm.as_mut().ok_or("Swarm not initialized")?;

       match swarm.listen_on(listen_addr.clone()) {
           Ok(_) => (),
           Err(error) => {
                debug!("NET: listen {:?} failed: {:?}", listen_addr, error);
                return Err(format!("Failed to start swarm"))
           }
       }
        
       self.dial_local_net().await

    }

    /// Dial all peers, and wait for at least one connection to be established.
    ///
    /// Dialing all peers will let the underlying gossipsub network know of their existence, thus
    /// allowing it to build up its mesh network.
    async fn dial_local_net(&mut self) -> Result<(), String> {
        // Start by dialing all peers other than ourselves, letting the underlying network layer know
        // of their existenec, allowing it to connect if required.
        let peers =  self.config.peers.as_ref().unwrap();
        for peer in peers {

            let dial_addr = utils::get_dial_addr(peer);
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

        // Wait for the first connection to be established or a timeout to occur.
        let timeout = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished { endpoint, .. } => {
                        info!(
                            "NET: Successfully connected to first peer on: {:?}",
                            endpoint.get_remote_address()
                        );
                        return;
                    },
                    _ => {}
                }
            }
        }).await;
        match timeout {
            Ok(_) => {
                info!("NET: Ready for client requests...");
                Ok(())
            }
            Err(e) => {
                error!("NET: Failed to connect to any peers");
                Err(format!("Failed to connect to any peers: {:?}", e))
            }
            _ => {
                error!("NET: Unexpected event while waiting for connection to first peer");
                Err("Unexpected event while waiting for connection to first peer".to_string())
            }
        }
    }

    
}

mod utils {
    use std::{
        collections::hash_map::DefaultHasher, 
        hash::{Hash, Hasher}, 
        time::Duration
    };

    use libp2p::{
        core::{muxing::StreamMuxerBox, transport::Boxed, upgrade}, 
        gossipsub::{self, Gossipsub, GossipsubMessage, IdentTopic as GossibsubTopic, MessageAuthenticity, MessageId, ValidationMode}, 
        identity::Keypair, 
        mplex, 
        multiaddr::Protocol, 
        noise::{self, AuthenticKeypair, X25519Spec}, 
        swarm::SwarmBuilder, 
        tcp::TokioTcpConfig, 
        Multiaddr, 
        PeerId, 
        Swarm, 
        Transport
    };

    use crate::types::config::NetworkPeer;

    // Create a keypair for authenticated encryption of the transport.
    pub fn create_noise_keys(keypair: &Keypair) -> AuthenticKeypair<X25519Spec> {
        noise::Keypair::<noise::X25519Spec>::new()
            .into_authentic(&keypair)
            .expect("Signing libp2p-noise static DH keypair failed.")
    }

    // Create a tokio-based TCP transport use noise for authenticated
    // encryption and Mplex for multiplexing of substreams on a TCP stream.
    pub fn create_tcp_transport(
        noise_keys: AuthenticKeypair<X25519Spec>,
    ) -> Boxed<(PeerId, StreamMuxerBox)> {
        TokioTcpConfig::new()
            .nodelay(true)
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(mplex::MplexConfig::new())
            .boxed()
    }

    // Create a Swarm to manage peers and events.
        pub fn create_gossipsub_swarm(
            topic: &GossibsubTopic,
            id_keys: Keypair,
            transport: Boxed<(PeerId, StreamMuxerBox)>,
            local_peer_id: PeerId,
        ) -> Swarm<Gossipsub> {
            // To content-address message, we can take the hash of message and use it as an ID.
            let message_id_fn = |message: &GossipsubMessage| {
            let mut s = DefaultHasher::new();
            message.data.hash(&mut s);
            MessageId::from(s.finish().to_string())
            };

            // Set a custom gossipsub
            let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
            // Meta data seems to be pusehd to to peers on every heartbeat, so they must be frequent
            // enough to ensure reliable delivery of messages.
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
            .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
            .build()
            .expect("Valid config");

            // build a gossipsub network behaviour
            let mut gossipsub: gossipsub::Gossipsub =
            gossipsub::Gossipsub::new(MessageAuthenticity::Signed(id_keys), gossipsub_config)
                .expect("Correct configuration");

            // subscribes to our topic
            gossipsub.subscribe(&topic).unwrap();

            // build the swarm
            SwarmBuilder::new(transport, gossipsub, local_peer_id)
            // We want the connection backgro&mut und tasks to be spawned onto the tokio runtime.
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build()
        }

        pub fn get_dial_addr(peer: &NetworkPeer) -> Multiaddr {
            let ip_version = "/ip4/";
        
            let dial_ip = &peer.ip;
            let dial_port = peer.port;
        
            // create Multiaddr from config data
            let dial_base_addr = format!("{}{}", ip_version, dial_ip);
            let mut dial_addr: Multiaddr = dial_base_addr.parse().unwrap();
            dial_addr.push(Protocol::Tcp(dial_port));
            return dial_addr;
        }

        }
