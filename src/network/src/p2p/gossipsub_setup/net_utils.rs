use futures::prelude::*;
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade},
    gossipsub,
    gossipsub::{
        Gossipsub, GossipsubEvent, GossipsubMessage, IdentTopic as GossibsubTopic,
        MessageAuthenticity, MessageId, ValidationMode,
    },
    identity::Keypair,
    mplex,
    noise::{self, AuthenticKeypair, X25519Spec},
    swarm::{SwarmBuilder, SwarmEvent},
    tcp::TokioTcpConfig,
    PeerId, Swarm, Transport,
};
use libp2p_dns::DnsConfig;
use log::debug;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    time::Duration,
};
use tokio::sync::mpsc::{Receiver, Sender};
use trust_dns_resolver::AsyncResolver;

use tokio::time;

// use crate::config::localnet_config::{config_service::*, deserialize::Config};
use crate::types::message::NetMessage;

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

//Attempt to create a DNS transport layer (not in use)
pub fn create_dns_transport() -> DnsConfig<TokioTcpConfig> {
    let tcp = TokioTcpConfig::new().nodelay(true);
    let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let transport = runtime.block_on(DnsConfig::system(tcp));
    let transport = match transport {
        Ok(config) => config,
        Err(error) => panic!("Problem opening dns: {:?}", error),
    };
    transport
}

//Attempt to define a DNS resolver fot the libp2p2 (not in use)
pub async fn dns_lookup() {
    let resolver = AsyncResolver::tokio_from_system_conf();
    let resolver = match resolver {
        Ok(resolver) => resolver,
        Err(error) => panic!("Problem opening dns: {:?}", error),
    };

    let response = tokio::spawn(async move {
        let _lookup_future = resolver.ipv4_lookup("nameserver");
        // Run the lookup until it resolves or errors
        //rt.block_on(lookup_future).unwrap()
    });
    println!(">> STATIC_NET: .........");
    let result = response.await.expect("The task being joined has panicked"); //.unwrap();

    //let address = result.iter().next().expect("no addresses returned!");
    format!(">> STATIC_NET: coversion: {:#?}", result);
    println!(">> STATIC_NET: ......... {:?}", result)
    // let result = match result {
    //     Ok(result) => result,
    //     Err(error) => error
    // };
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

// kick off tokio::select event loop to handle events
pub async fn run_event_loop(
    swarm: &mut Swarm<Gossipsub>,
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
                for (peer, _) in swarm.behaviour().all_peers() {
                    debug!("- {}", peer);
                }

                debug!("NET: My currently connected mesh peers: ");
                for peer in swarm.behaviour().all_mesh_peers() {
                    debug!("- {}", peer);
                }
            }
            // reads msg from the channel and publish it to the network
            msg = outgoing_msg_receiver.recv() => {
                if let Some(data) = msg {
                    debug!("NET: Sending a message");
                    swarm.behaviour_mut().publish(topic.clone(), data).expect("Publish error");
                }
                // todo: Terminate the loop
                // if msg is None (i.e., chn_out has been closed and no new message will ever be received)?
            }
            // polls swarm events
            event = swarm.select_next_some() => match event {
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
