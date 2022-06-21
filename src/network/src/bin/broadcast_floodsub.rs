// use cosmos_crypto::dl_schemes::dl_groups::ed25519::Ed25519;
use floodsub::Topic;
use futures::StreamExt;
use libp2p::{
    core::upgrade,
    floodsub::{self, Floodsub},
    identity,
    mdns::{Mdns},
    mplex,
    Multiaddr,
    noise,
    swarm::{SwarmBuilder, SwarmEvent},
    // `TokioTcpConfig` is available through the `tcp-tokio` feature.
    tcp::TokioTcpConfig,
    Transport,
    PeerId,
};
use once_cell::sync::Lazy;
use std::error::Error;
use tokio::{
    sync::mpsc,
};

use network::setup::swarm_behaviour::FloodsubMdnsBehaviour;
use network::send::send::{send_floodsub_vecu8, message_sender};

static FLOODSUB_TOPIC: Lazy<Topic> = Lazy::new(|| Topic::new("share"));

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    // Create a random PeerId
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());
    println!("Local peer id: {:?}", peer_id);

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

    // Create a Swarm to manage peers and events.
    let mut swarm = {
        let mdns = Mdns::new(Default::default()).await?;
        let mut behaviour = FloodsubMdnsBehaviour {
            floodsub: Floodsub::new(peer_id.clone()),
            mdns,
        };

        behaviour.floodsub.subscribe(FLOODSUB_TOPIC.clone());

        SwarmBuilder::new(transport, behaviour, peer_id)
            // We want the connection backgro&mut und tasks to be spawned onto the tokio runtime.
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build()
    };

    // Reach out to another node if specified
    if let Some(to_dial) = std::env::args().nth(1) {
        let addr: Multiaddr = to_dial.parse()?;
        swarm.dial(addr)?;
        println!("Dialed {:?}", to_dial);
    }

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    // create channel, spawn sender
    let (tx, mut rx) = mpsc::unbounded_channel();

    // sends a Vec<u8> into the channel 
    let my_vec: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
    tokio::spawn(message_sender(my_vec, tx));

    loop {
        tokio::select! {
            // reads msgs from the channel and broadcasts it to the network
            msg = rx.recv() => {
                if let Some(msg) = &msg {
                    send_floodsub_vecu8(&mut swarm, &FLOODSUB_TOPIC, msg.to_vec())
                }
            }
            // handles events produced by the swarm
            event = swarm.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    println!("Listening on {:?}", address);
                }
            }
        }
    }
}