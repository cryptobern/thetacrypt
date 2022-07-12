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
    multiaddr::{Multiaddr, Protocol},
    PeerId};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    time::Duration,
};
use tokio::sync::mpsc::{Receiver, Sender};

use crate::config::deserialize::{Config, load_config};
use crate::types::message::P2pMessage;

const CONFIG_PATH: &str = "../network/src/config/config.toml";

pub async fn init(
    chn_out_recv: Receiver<P2pMessage>,
    chn_in_send: Sender<P2pMessage>,
    my_peer_id: u32, //todo: probably can also be moved to a conf file
    ) {
        env_logger::init();

        // load config file
        let config = load_config(CONFIG_PATH.to_string());
        
        // Create a Gossipsub topic
        let topic: GossibsubTopic = GossibsubTopic::new("gossipsub broadcast");

        // Create a random Keypair and PeerId (hash of the public key)
        let id_keys = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(id_keys.public());
        println!(">> NET: Local peer id: {:?}", local_peer_id);

        // Create a keypair for authenticated encryption of the transport.
        let noise_keys = create_noise_keys(&id_keys);

        // Create a tokio-based TCP transport, use noise for authenticated
        // encryption and Mplex for multiplexing of substreams on a TCP stream.
        let transport = create_tcp_transport(noise_keys);
        
        // Create a Swarm to manage peers and events.
        let mut swarm = create_gossipsub_swarm(&topic, id_keys.clone(), transport, local_peer_id);

        // load listener address from config file
        let listen_addr = get_listen_addr(&config, my_peer_id);
        println!(">> NET: Listening on: {}", listen_addr);

        // bind port to listener address
        match swarm.listen_on(listen_addr.clone()) {
            Ok(_) => (),
            Err(error) => println!(">> NET: listen {:?} failed: {:?}", listen_addr, error),
        }

        // dial another peer in the network
        dial(&mut swarm, config, my_peer_id).await;

        // kick off tokio::select event loop to handle events
        run_event_loop(&mut swarm, topic, chn_out_recv, chn_in_send).await;
}

// return listening address
pub fn get_listen_addr(config: &Config, my_peer_id: u32) -> Multiaddr {
    let listen_port = get_p2p_port(config, my_peer_id);

    format!("{}{}", config.servers.listen_address, listen_port)
        .parse()
        .expect(&format!(">> NET: Fatal error: Could not open listen port {}.", listen_port))
}

// load port number from config file
pub fn get_p2p_port(config: &Config, peer_id: u32) -> u32 {
    let listn_port: u32 = 27000; // default port number

    for (k, id) in config.servers.ids.iter().enumerate() {
        if *id == peer_id {
            return config.servers.p2p_ports[k];
        }
    }
    return listn_port;
}

// load ip from config file
pub fn get_ip(config: &Config, peer_id: u32) -> String {
    let listn_port: String = "127.0.0.1".to_string(); // default ip

    for (k, id) in config.servers.ids.iter().enumerate() {
        if *id == peer_id {
            return config.servers.ips[k].to_string();
        }
    }
    return listn_port.to_string();
}

// return Multiaddr from config file
pub fn get_dial_addr(config: &Config, peer_id: u32) -> Multiaddr {
    let ip_format = "/ip4/";

    let dial_ip = get_ip(config, peer_id);
    let dial_port = get_p2p_port(config, peer_id);

    // create Multiaddr from config data
    let dial_base_addr = format!("{}{}", ip_format, dial_ip);
    let mut dial_addr: Multiaddr = dial_base_addr.parse().unwrap();
    dial_addr.push(Protocol::Tcp(dial_port.try_into().unwrap()));
    return dial_addr;
}

// dial another node, if it fails, retry another peer
pub async fn dial(swarm: &mut Swarm<Gossipsub>, config: Config, my_peer_id: u32) {

    let mut index = 0;
    let n = config.servers.ids.len();

    loop {
        let peer_id = config.servers.ids[index];
        if peer_id == my_peer_id {
            index = (index + 1) % n;
            continue;
        } else {
            let dial_addr = get_dial_addr(&config, peer_id);
            match swarm.dial(dial_addr.clone()) {
                Ok(_) => {
                    println!(">> NET: Dialed {:?}", dial_addr);
                    match swarm.select_next_some().await {
                        SwarmEvent::ConnectionEstablished {..} => {
                            println!(">> NET: Connection to {dial_addr} successful.");
                            break},
                        SwarmEvent::OutgoingConnectionError {peer_id: _, error: _} => {
                            index = (index + 1) % n;
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
    // add an explicit peer if one was provided
    if let Some(explicit) = std::env::args().nth(2) {
        let explicit = explicit.clone();
        match explicit.parse() {
            Ok(id) => gossipsub.add_explicit_peer(&id),
            Err(err) => println!(">>NET: Failed to parse explicit peer id: {:?}", err),
        }
    }
    // build the swarm
    // libp2p::Swarm::new(transport, gossipsub, local_peer_id)
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
    mut chn_out_recv: Receiver<P2pMessage>,
    chn_send_in: Sender<P2pMessage>) -> ! {
        println!(">> NET: Starting event loop.");
        loop {
            tokio::select! {
                // reads msgs from the channel and broadcasts it to the network as a swarm event
                msg = chn_out_recv.recv() => {
                    let data = msg.expect(">> NET: Fatal error: chn_out_recv unexpectedly closed.");
                    println!(">> NET: Sending a message");
                    swarm.behaviour_mut()
                         .publish(topic.clone(), data)
                         .expect("Publish error");
                    // todo: Terminate the loop 
                    // if msg is None (i.e., chn_out has been closed and no new message will ever be received)?
                },
                // polls swarm events
                event = swarm.select_next_some() => match event {
                    // handles (incoming) Gossipsub-Message
                    SwarmEvent::Behaviour(GossipsubEvent::Message {
                        propagation_source: _peer_id,
                        message_id: _id,
                        message,
                    }) => {
                        // add incoming message to internal channel
                        println!(">> NET: Received a message");
                        chn_send_in.send(message.data.into()).await.unwrap();
                    }
                    // handles NewListenAddr event
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!(">> NET: Listening on {:?}", address);
                    }
                    
                    _ => {}
                }
            }
        }
}