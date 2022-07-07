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
    Multiaddr,
    PeerId};
use serde::{Serialize, Deserialize};
use std::{collections::hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::{
    sync::mpsc::{Receiver, Sender},
};

use std::fs;
use std::process::exit;
use toml;

//todo: Move this to a new types crate
#[derive(Serialize, Deserialize, Debug)]
pub struct P2pMessage {
    pub instance_id: String,
    pub message_data: Vec<u8>
}
impl From<P2pMessage> for Vec<u8> {
    fn from(p2p_message: P2pMessage) -> Self {
        // serde_json::to_string(&p2p_message).unwrap().as_bytes().to_vec()
        serde_json::to_string(&p2p_message).expect("Error in From<P2pMessage> for Vec<u8>").into_bytes()
    }
}
impl From<Vec<u8>> for P2pMessage {
    fn from(vec: Vec<u8>) -> Self {
        serde_json::from_str::<P2pMessage>(&String::from_utf8(vec).expect("Error in From<Vec<u8>> for P2pMessage")).unwrap()
    }
}

#[derive(Deserialize)]
pub struct Data {
    servers: Server,
}

#[derive(Deserialize)]
pub struct Server {
    ids: Vec<u32>,
    // ips: Vec<String>,
    ports: Vec<u32>,
}


pub async fn init(
    chn_out_recv: Receiver<P2pMessage>,
    chn_in_send: Sender<P2pMessage>,
    local_deployment: bool,
    peer_id: u32, //todo: probably can also be moved to a conf file
    num_peers: u32 //todo: remove
    ){
    env_logger::init();

    let config = load_config();
    
    // Create a Gossipsub topic
    let topic: GossibsubTopic = GossibsubTopic::new("gossipsub broadcast");

    let listen_addr = get_listen_addr(&config, peer_id);
    let dial_addr = get_dial_addr(&config, peer_id);

    println!(">> NET: listen_addr: {}", listen_addr);
    println!(">> NET: dial_addr: {}", dial_addr);

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

    // bind port to given listener address
    match swarm.listen_on(listen_addr.clone()) {
        Ok(_) => (),
        Err(error) => println!(">> NET: listen {:?} failed: {:?}", listen_addr, error),
    }

    loop {
        match swarm.dial(dial_addr.clone()) {
            Ok(_) => {
                println!(">> NET: Dialed {:?}", dial_addr);
                match swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished {..} => break,
                    SwarmEvent::OutgoingConnectionError {peer_id, error} => {
                            println!(">> NET: Connection to {dial_addr} NOT successful. Retrying in 2 sec.");
                            tokio::time::sleep(Duration::from_millis(2000)).await;
                    }
                    _ => {}
                }
            },
            Err(e) => println!(">> NET: Dial {:?} failed: {:?}", dial_addr, e),
        };
    }
    println!(">> NET: Connection to {dial_addr} successful.");

    // kick off tokio::select event loop to handle events
    run_event_loop(&mut swarm, topic, chn_out_recv, chn_in_send).await;
}

// load config file
pub fn load_config() -> Data {
    let contents = match fs::read_to_string("../network/src/p2p/config.toml") {
        // If successful return the files text as `contents`.
        Ok(c) => c,
        // Handle the `error` case.
        Err(_) => {
            // Write `msg` to `stderr`.
            eprintln!("Could not read file `{}`", "../network/src/p2p/config.toml");
            // Exit the program with exit code `1`.
            exit(1);
        }
    };

    // Use a `match` block to return the file `contents` as a `Data struct: Ok(d)` or handle any `errors: Err(_)`.
    let data: Data = match toml::from_str(&contents) {
        // If successful, return data as `Data` struct.
        Ok(d) => d,
        // Handle the `error` case.
        Err(e) => {
            // Write `msg` to `stderr`.
            eprintln!("Unable to load data from `{}`", "../network/src/p2p/config.toml");
            println!("################ {}", e);
            // Exit the program with exit code `1`.
            exit(1);
        }
    };
    return data;
}

// return listening address
pub fn get_listen_addr(config: &Data, peer_id: u32) -> Multiaddr {
    let listen_port = get_listen_port(config, peer_id);

    format!("{}{}", "/ip4/0.0.0.0/tcp/", listen_port)
        .parse()
        .expect(&format!(">> NET: Fatal error: Could not open listen port {}.", listen_port))
}

// load port number from config file
pub fn get_listen_port(config: &Data, peer_id: u32) -> u32 {
    let listn_port: u32 = 27000; // default port number

    for (k, id) in config.servers.ids.iter().enumerate() {
        if *id == peer_id {
            return config.servers.ports[k];
        }
    }
    return listn_port;
}

// return dialing address
pub fn get_dial_addr(config: &Data, peer_id: u32) -> Multiaddr {
    let dial_port = get_dial_port(config, peer_id);

    format!("{}{}", "/ip4/127.0.0.1/tcp/", dial_port)
        .parse()
        .expect(&format!(">> NET: Fatal error: Could not dial peer at port {}.", dial_port))
}

// load port number from config file
pub fn get_dial_port(config: &Data, peer_id: u32) -> u32 {
    let dial_port: u32 = 27000; // default port number

    for (k, id) in config.servers.ids.iter().enumerate() {
        if *id != peer_id {
            return config.servers.ports[k];
        }
    }
    return dial_port;
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
                        propagation_source: peer_id,
                        message_id: id,
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