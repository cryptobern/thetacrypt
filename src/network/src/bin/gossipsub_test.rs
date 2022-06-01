use libp2p_gossipsub::GossipsubEvent;
use libp2p_core::{identity::Keypair,transport::{Transport, MemoryTransport}, Multiaddr};
use libp2p_gossipsub::MessageAuthenticity;
use std::error::Error;

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {

    // Set up an encrypted TCP Transport over the Mplex
    // This is test transport (memory).
    let noise_keys = libp2p_noise::Keypair::<libp2p_noise::X25519Spec>::new().into_authentic(&local_key).unwrap();
    let transport = MemoryTransport::default()
            .upgrade(libp2p_core::upgrade::Version::V1)
            .authenticate(libp2p_noise::NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(libp2p_mplex::MplexConfig::new())
            .boxed();

    // Create a Gossipsub topic
    let topic = libp2p_gossipsub::IdentTopic::new("example");

    // Set the message authenticity - How we expect to publish messages
    // Here we expect the publisher to sign the message with their key.
    let message_authenticity = MessageAuthenticity::Signed(local_key);

    // Create a Swarm to manage peers and events
    let mut swarm = {
        // set default parameters for gossipsub
        let gossipsub_config = libp2p_gossipsub::GossipsubConfig::default();
        // build a gossipsub network behaviour
        let mut gossipsub: libp2p_gossipsub::Gossipsub =
            libp2p_gossipsub::Gossipsub::new(message_authenticity, gossipsub_config).unwrap();
        // subscribe to the topic
        gossipsub.subscribe(&topic);
        // create the swarm
        libp2p_swarm::Swarm::new(
            transport,
            gossipsub,
            local_peer_id,
        )
    };

    // Listen on a memory transport.
    let memory: Multiaddr = libp2p_core::multiaddr::Protocol::Memory(10).into();
    let addr = swarm.listen_on(memory).unwrap();
    println!("Listening on {:?}", addr);

    Ok(())

}