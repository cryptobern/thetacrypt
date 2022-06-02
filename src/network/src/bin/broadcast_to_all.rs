// use tokio_stream::{self as stream};
use futures::StreamExt;
use std::error::Error;
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
use floodsub::Topic;
use tokio::io::{self, AsyncBufReadExt};
use deliver::deliver::MyBehaviour;
use broadcast::broadcast::{send, send_async};
// use tokio::time::{sleep, Duration};

mod deliver;
mod broadcast;

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

    // Create a Floodsub topic
    let floodsub_topic = Topic::new("shares");

    // Create a Swarm to manage peers and events.
    let mut swarm = {
        let mdns = Mdns::new(Default::default()).await?;
        let mut behaviour = MyBehaviour {
            floodsub: Floodsub::new(peer_id.clone()),
            mdns,
        };

        behaviour.floodsub.subscribe(floodsub_topic.clone());

        SwarmBuilder::new(transport, behaviour, peer_id)
            // We want the connection background tasks to be spawned
            // onto the tokio runtime.
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

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    loop {
        tokio::select! {
            // _ = send_async(&mut swarm, &floodsub_topic, &a) => {
            //     println!("do_stuff_async() completed first")
            // }
            line = stdin.next_line() => {
                let line = line?.expect("stdin closed");
                // by hitting "enter" the send function is triggered
                let my_share: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
                send(&mut swarm, &floodsub_topic, my_share);
                // send_async(&mut swarm, &floodsub_topic);
                
            }
            event = swarm.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    println!("Listening on {:?}", address);
                }
            }
        }
    }

}