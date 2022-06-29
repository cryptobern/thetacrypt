use crate::setup::swarm_behaviour::FloodsubMdnsBehaviour;
use floodsub::Topic;
use futures::StreamExt;
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade},
    floodsub::{self, Floodsub},
    identity::{self, Keypair},
    mplex,
    noise::{AuthenticKeypair, X25519Spec, self},
    PeerId,
    tcp::TokioTcpConfig,
    Transport, Swarm, mdns::Mdns, swarm::{SwarmBuilder, SwarmEvent}};
use once_cell::sync::Lazy;
use std::error::Error;
use tokio::sync::mpsc::UnboundedReceiver;

pub async fn init(topic: Lazy<Topic>, channel_receiver: UnboundedReceiver<Vec<u8>>) {
    env_logger::init();

    // TODO: get listen address from tendermint RPC endpoint
    let listen_addr = "/ip4/0.0.0.0/tcp/0";
    // Create a random PeerId
    // TODO: get local keypair and peer id from tendermint RPC endpoint
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());
    println!("Local peer id: {:?}", peer_id);

    // Create a keypair for authenticated encryption of the transport.
    let noise_keys = create_noise_keys(id_keys);

    // Create a tokio-based TCP transport, use noise for authenticated
    // encryption and Mplex for multiplexing of substreams on a TCP stream.
    let transport = create_tcp_transport(noise_keys);

    // crate a Swarm to manage peers and events from floodsub protocol
    let mut swarm = create_floodsub_swarm_behaviour(
        topic.clone(), peer_id, transport).await.unwrap();

    // bind port to given listener address
    match listen_on(&mut swarm, listen_addr.to_string()).await {
        Ok(()) => (),
        Err(err) => println!("error: {}", err),
    }

    // kick off tokio::select event loop to handle events
    run_event_loop(channel_receiver, &mut swarm, topic).await;

}

// Create a keypair for authenticated encryption of the transport.
fn create_noise_keys(keypair: Keypair) -> AuthenticKeypair<X25519Spec> {
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
async fn create_floodsub_swarm_behaviour(
    topic: Topic,
    local_peer_id: PeerId,
    transport: Boxed<(PeerId, StreamMuxerBox)>) -> Result<Swarm<FloodsubMdnsBehaviour>, Box<dyn Error>> {
        let mdns = Mdns::new(Default::default()).await?;
        let mut behaviour = FloodsubMdnsBehaviour {
            floodsub: Floodsub::new(local_peer_id.clone()),
            mdns,
        };

        behaviour.floodsub.subscribe(topic);

        Ok(SwarmBuilder::new(transport, behaviour, local_peer_id)
        // We want the connection backgro&mut und tasks to be spawned onto the tokio runtime.
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build())
    }

// Listen on all interfaces of given address
async fn listen_on(swarm: &mut Swarm<FloodsubMdnsBehaviour>, address: String) -> Result<(), Box<dyn Error>> {
    swarm.listen_on(address.parse()?)?;
    Ok(())
}

// kick off tokio::select event loop to handle events
async fn run_event_loop(
    mut channel_receiver: UnboundedReceiver<Vec<u8>>, swarm: &mut Swarm<FloodsubMdnsBehaviour>, topic: Lazy<Topic>) {
    loop {
        tokio::select! {
            // reads msgs from the channel and broadcasts it to the network
            msg = channel_receiver.recv() => {
                if let Some(msg) = &msg {
                    println!("SEND: {:#?}", msg.to_vec());
                    swarm.behaviour_mut().floodsub.publish(topic.clone(), msg.to_vec());
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