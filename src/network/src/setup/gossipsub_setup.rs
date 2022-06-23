use async_std::io;
use env_logger::{Builder, Env};
use futures::{prelude::*, select};
use libp2p::Swarm;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::gossipsub::{MessageId, Gossipsub};
use libp2p::gossipsub::{
    GossipsubEvent, GossipsubMessage, IdentTopic as GossibsubTopic, MessageAuthenticity, ValidationMode,
};
use libp2p::identity::Keypair;
use libp2p::{gossipsub, identity, swarm::SwarmEvent, Multiaddr, PeerId};
use std::collections::hash_map::DefaultHasher;
// use std::error::Error;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use crate::deliver::deliver::HandleMsg;

// use network::deliver::deliver::HandleMsg;

pub async fn init(topic: GossibsubTopic, listen_addr: Multiaddr, dial_addr: Multiaddr) {
    Builder::from_env(Env::default().default_filter_or("info")).init();

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines().fuse();

    // Create a random PeerId
    // TODO: get local keypair and peer id from tendermint RPC endpoint
    let local_key = identity::Keypair::generate_ed25519();
    // let local_peer_id = PeerId::from(local_key.public());
    // println!("Local peer id: {:?}", local_peer_id);

    // Set up an encrypted TCP Transport over the Mplex and Yamux protocols
    // let transport = create_enc_tcp_transport(local_key);
    let transport = libp2p::development_transport(local_key.clone()).await;

    match transport {
        Ok(transport) => {
            let mut swarm = create_swarm(local_key, &topic, transport);
            // Listen on all interfaces and whatever port the OS assigns
            // swarm.listen_on(listen_addr.parse().unwrap());
            swarm.listen_on(listen_addr); 

            // Reach out to another node
            // let address: Multiaddr = dial.parse().expect("User to provide valid address.");
            match swarm.dial(dial_addr.clone()) {
                Ok(_) => println!("Dialed {:?}", dial_addr),
                Err(e) => println!("Dial {:?} failed: {:?}", dial_addr, e),
            };

            loop {
                select! {
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
        },
        Err(error) => println!("transport error {}", error),
    };
}

fn create_swarm(local_key: Keypair, topic: &GossibsubTopic, transport: Boxed<(PeerId, StreamMuxerBox)>) -> Swarm<Gossipsub> {

    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);
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
        gossipsub::Gossipsub::new(MessageAuthenticity::Signed(local_key), gossipsub_config)
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
    libp2p::Swarm::new(transport, gossipsub, local_peer_id)
}

// Listen on all interfaces and the assigned port
async fn listen_on(mut swarm: Swarm<Gossipsub>, address: String) {
    // swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();
    swarm.listen_on(address.parse().unwrap()).unwrap();
}

// async fn run_event_loop(swarm: Swarm<Gossipsub>, topic: GossibsubTopic) {
//     loop {
//         select! {
//             line = stdin.select_next_some() => {
//                 if let Err(e) = swarm
//                     .behaviour_mut()
//                     .publish(topic.clone(), line.expect("Stdin not to close").as_bytes())
//                 {
//                     println!("Publish error: {:?}", e);
//                 }
//             },
//             event = swarm.select_next_some() => match event {
//                 SwarmEvent::Behaviour(GossipsubEvent::Message {
//                     propagation_source: peer_id,
//                     message_id: id,
//                     message,
//                 }) => message.handle_msg(),
//                 SwarmEvent::NewListenAddr { address, .. } => {
//                     println!("Listening on {:?}", address);
//                 }
//                 _ => {}
//             }
//         }
//     }
// }