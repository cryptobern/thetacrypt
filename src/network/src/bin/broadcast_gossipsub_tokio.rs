use async_std::io;
use futures::prelude::*;
use libp2p::swarm::SwarmBuilder;
use libp2p::{Transport, mplex, gossipsub};
use libp2p::tcp::TokioTcpConfig;
use libp2p::{
    core::upgrade,
    gossipsub::{
        MessageId,
        GossipsubEvent,
        GossipsubMessage,
        IdentTopic as GossibsubTopic,
        MessageAuthenticity,
        ValidationMode},
    identity,
    noise,
    swarm::SwarmEvent,
    Multiaddr,
    PeerId};
use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::{
    sync::mpsc::{self, UnboundedSender},
    time,
}; // 1.16.1

use network::deliver::deliver::HandleMsg;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    // Create a random PeerId
    let id_keys = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(id_keys.public());
    println!("Local peer id: {:?}", local_peer_id);

    // Create a keypair for authenticated encryption of the transport.
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&id_keys)
        .expect("Signing libp2p-noise static DH keypair failed.");

    // Create a tokio-based TCP transport use noise for authenticated
    // encryption and Mplex for multiplexing of substreams on a TCP stream.
    let transport = TokioTcpConfig::new()
        .nodelay(true)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .boxed();

    let topic = GossibsubTopic::new("gossip-share");
    // Create a Swarm to manage peers and events
    let mut swarm = {
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
                Err(err) => println!("Failed to parse explicit peer id: {:?}", err),
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
    };

    // Listen on all interfaces and whatever port the OS assigns
    swarm
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .unwrap();

    // Reach out to another node if specified
    if let Some(to_dial) = std::env::args().nth(1) {
        let address: Multiaddr = to_dial.parse().expect("User to provide valid address.");
        match swarm.dial(address.clone()) {
            Ok(_) => println!("Dialed {:?}", address),
            Err(e) => println!("Dial {:?} failed: {:?}", address, e),
        };
    }

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines().fuse();

    // create channel with sender and receiver
    let (tx, mut rx) = mpsc::unbounded_channel();

    // spawns a thread with the channel sender to add Vec<u8> messages to the channel 
    let my_vec: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
    tokio::spawn(message_sender(my_vec, tx));

    // Kick it off
    loop {
        tokio::select! {
            // reads msgs from the channel and broadcasts it to the network
            msg = rx.recv() => {
                println!("SEND: {:?}", msg);
                if let Err(e) = swarm
                    .behaviour_mut()
                    .publish(topic.clone(), msg.expect("Stdin not to close").to_vec())
                {
                    println!("Publish error: {:?}", e);
                }
            },
            line = stdin.select_next_some() => {
                if let Err(e) = swarm
                    .behaviour_mut()
                    .publish(topic.clone(), line.expect("Stdin not to close").as_bytes())
                {
                    println!("Publish error: {:?}", e);
                }
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(GossipsubEvent::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    message,
                }) => message.handle_msg(),
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Listening on {:?}", address);
                }
                _ => {}
            }
        }
    }
}

async fn message_sender(mut msg: Vec<u8>, foo_tx: UnboundedSender<Vec<u8>>) {
    for count in 0.. {
        msg[0] = count; // to keep track of the messages
        msg[1] = rand::random(); // to prevent dublicate messages
        foo_tx.send(msg.to_vec()).unwrap();

        time::sleep(Duration::from_millis(1000)).await;
    }
}