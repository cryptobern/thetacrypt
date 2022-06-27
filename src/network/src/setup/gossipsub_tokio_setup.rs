use futures::prelude::*;
use libp2p::swarm::SwarmBuilder;
use libp2p::{Transport, mplex, gossipsub};
use libp2p::tcp::TokioTcpConfig;
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade},
    gossipsub::{
        MessageId,
        GossipsubEvent,
        GossipsubMessage,
        IdentTopic as GossibsubTopic,
        MessageAuthenticity,
        ValidationMode},
    identity::{self, Keypair},
    noise::{AuthenticKeypair, X25519Spec, self},
    swarm::SwarmEvent,
    Multiaddr,
    PeerId};
use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::{
    sync::mpsc::UnboundedReceiver,
};

use crate::deliver::deliver::HandleMsg;

pub async fn init(topic: GossibsubTopic, listen_addr: Multiaddr, dial_addr: Multiaddr, mut channel_receiver: UnboundedReceiver<Vec<u8>>) {
    env_logger::init();

    // TODO: get listen address from tendermint RPC endpoint
    // let listen_addr = "/ip4/0.0.0.0/tcp/0";
    // Create a random PeerId
    // TODO: get local keypair and peer id from tendermint RPC endpoint
    let id_keys = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(id_keys.public());
    println!("Local peer id: {:?}", local_peer_id);

    // Create a keypair for authenticated encryption of the transport.
    let noise_keys = create_noise_keys(&id_keys);

    // Create a tokio-based TCP transport, use noise for authenticated
    // encryption and Mplex for multiplexing of substreams on a TCP stream.
    let transport = create_tcp_transport(noise_keys);
    
    // let topic = GossibsubTopic::new("gossip-share");
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

    // bind port to given listener address
    match swarm.listen_on(listen_addr.clone()) {
        Ok(_) => (),
        Err(error) => println!("listen {:?} failed: {:?}", listen_addr, error),
    }

    match swarm.dial(dial_addr.clone()) {
        Ok(_) => println!("Dialed {:?}", dial_addr),
        Err(e) => println!("Dial {:?} failed: {:?}", dial_addr, e),
    };

    // Kick it off
    loop {
        tokio::select! {
            // reads msgs from the channel and broadcasts it to the network
            msg = channel_receiver.recv() => {
                println!("SEND: {:?}", msg);
                if let Err(e) = swarm
                    .behaviour_mut()
                    .publish(topic.clone(), msg.expect("Stdin not to close").to_vec())
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
// async fn create_floodsub_swarm_behaviour(
//     topic: Topic,
//     local_peer_id: PeerId,
//     transport: Boxed<(PeerId, StreamMuxerBox)>) -> Result<Swarm<FloodsubMdnsBehaviour>, Box<dyn Error>> {
//         let mdns = Mdns::new(Default::default()).await?;
//         let mut behaviour = FloodsubMdnsBehaviour {
//             floodsub: Floodsub::new(local_peer_id.clone()),
//             mdns,
//         };

//         behaviour.floodsub.subscribe(topic);

//         Ok(SwarmBuilder::new(transport, behaviour, local_peer_id)
//         // We want the connection backgro&mut und tasks to be spawned onto the tokio runtime.
//             .executor(Box::new(|fut| {
//                 tokio::spawn(fut);
//             }))
//             .build())
//     }

// // Listen on all interfaces of given address
// async fn listen_on(swarm: &mut Swarm<Gossipsub>, address: String) -> Result<(), Box<dyn Error>> {
//     swarm.listen_on(address.parse()?)?;
//     Ok(())
// }