use futures::prelude::*;
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade},
    gossipsub,
    gossipsub::{
        MessageId,
        Gossipsub,
        GossipsubEvent,
        GossipsubMessage,
        IdentTopic as GossibsubTopic,
        MessageAuthenticity,
        ValidationMode},
    identity::{self, Keypair},
    mplex,
    noise::{AuthenticKeypair, X25519Spec, self},
    Swarm,
    swarm::{SwarmBuilder, SwarmEvent},
    tcp::TokioTcpConfig,
    Transport,
    PeerId};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    // io::{stdout, Write},
    time::Duration,
};
use tokio::sync::mpsc::{Receiver, Sender};

use crate::config::tendermint_config::{config_service::*, deserialize::Config};
use crate::types::message::P2pMessage;

pub async fn init(
    outgoing_msg_receiver: Receiver<P2pMessage>,
    incoming_msg_sender: Sender<P2pMessage>,
    tendermint_config: Config
) {
    env_logger::init();

    let tendermint_node_id = get_tendermint_node_id().await;
    println!(">> NET: Tendermint node id {:?}", tendermint_node_id);
    
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
    let mut swarm = create_gossipsub_swarm(&topic, id_keys.clone(), transport, local_peer_id);

    // load listener address from config file
    let listen_addr = get_p2p_listen_addr(&tendermint_config);
    println!(">> NET: Listening for P2P on: {}", listen_addr);
    
    // bind port to listener address
    match swarm.listen_on(listen_addr.clone()) {
        Ok(_) => (),
        Err(error) => println!(">> NET: listen {:?} failed: {:?}", listen_addr, error),
    }
    
    // dial another peer in the network
    dial_tendermint_net(&mut swarm, tendermint_config).await;
    
    // kick off tokio::select event loop to handle events
    run_event_loop(&mut swarm, topic, outgoing_msg_receiver, incoming_msg_sender).await;
}

pub async fn dial_tendermint_net(
    swarm: &mut Swarm<Gossipsub>,
    config: crate::config::tendermint_config::deserialize::Config
) {
    let mut index = 0;
    let ips = get_node_ips().await; // get ips of all other nodes in the network
    let n = ips.len();

    loop {
        let ip = &ips[index];
        let dial_addr = get_dial_addr(config.p2p_port, ip.to_string());
        match swarm.dial(dial_addr.clone()) {
            Ok(_) => {
                // println!(">> NET: Dialed {:?}", dial_addr);
                match swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished {endpoint, ..} => {
                        println!();
                        // wrong output --> might display dial_addr from a node that is not running yet!
                        // println!(">> NET: Connected to dial_addr: {:?}", dial_addr); 

                        // only useful output when the endpoint is of Enum variant "Dialer".
                        // from https://docs.rs/libp2p/latest/libp2p/core/enum.ConnectedPoint.html:
                        // "For Dialer, this returns address. For Listener, this returns send_back_addr."
                        println!(">> NET: Connected to endpoint: {:?}", endpoint.get_remote_address());

                        // println!(">> NET: Connected to the network!");
                        println!(">> NET: Ready for client requests ...");
                        break
                    }
                    SwarmEvent::OutgoingConnectionError {..} => {
                        index = (index + 1) % n; // try next peer address in next iteration

                        println!(">> NET: Connection to {dial_addr} NOT successful. Retrying in 2 sec.");
                        tokio::time::sleep(Duration::from_millis(2000)).await;
                    }
                    _ => {}
                }
            },
            Err(e) => println!(">> NET: Dial {:?} failed: {:?}", dial_addr, e),
        };    
    }
}

// Create a keypair for authenticated encryption of the transport.
fn create_noise_keys(keypair: &Keypair) -> AuthenticKeypair<X25519Spec> {
    noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&keypair)
        .expect("Signing libp2p-noise static DH keypair failed.")
}

// Create a tokio-based TCP transport use noise for authenticated
// encryption and Mplex for multiplexing of substreams on a TCP stream.
fn create_tcp_transport(noise_keys: AuthenticKeypair<X25519Spec>) -> Boxed<(PeerId, StreamMuxerBox)> {
    TokioTcpConfig::new()
        .nodelay(true)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .boxed()
}

// Create a Swarm to manage peers and events.
fn create_gossipsub_swarm(
    topic: &GossibsubTopic, id_keys: Keypair, transport: Boxed<(PeerId, StreamMuxerBox)>, local_peer_id: PeerId) -> Swarm<Gossipsub> {
    
        // To content-address message, we can take the hash of message and use it as an ID.
    let message_id_fn = |message: &GossipsubMessage| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        MessageId::from(s.finish().to_string())
    };

    // Set a custom gossipsub
    let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
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
async fn run_event_loop(
    swarm: &mut Swarm<Gossipsub>,
    topic: GossibsubTopic,
    mut outgoing_msg_receiver: Receiver<P2pMessage>,
    incoming_msg_sender: Sender<P2pMessage>) -> ! {
        loop {
            tokio::select! {
                // reads msg from the channel and publish it to the network
                msg = outgoing_msg_receiver.recv() => {
                    if let Some(data) = msg {
                        println!(">> NET: Sending message");
                        swarm.behaviour_mut().publish(topic.clone(), data).expect("Publish error");
                    }
                    // todo: Terminate the loop 
                    // if msg is None (i.e., chn_out has been closed and no new message will ever be received)?
                }
                // polls swarm events
                event = swarm.select_next_some() => match event {
                    // handles (incoming) Gossipsub-Message
                    SwarmEvent::Behaviour(GossipsubEvent::Message {message, ..}) => {
                        println!(">> NET: Received message");
                        // add incoming message to internal channel
                        incoming_msg_sender.send(message.data.into()).await.unwrap();
                    }
                    // handles NewListenAddr event
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!(">> NET: Listening on {:?}", address);
                    }
                    
                    // // tells us with which endpoints we are actually connected with
                    // // not nice to display since multiple events are produced
                    // SwarmEvent::ConnectionEstablished { endpoint, .. } => {
                    //     if endpoint.is_dialer() {
                    //         println!(">> NET: Connected with {:?}", endpoint.get_remote_address());
                    //     }
                    // }
                    
                    _ => {}
                }
            }
        }
}