use futures::prelude::*;
use libp2p::{identity, Multiaddr, PeerId};
use libp2p::ping::{Ping, PingConfig};
use libp2p::swarm::{Swarm, SwarmEvent};
use std::error::Error;

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);

    let transport = libp2p::development_transport(local_key).await?;

    let behaviour = Ping::new(PingConfig::new().with_keep_alive(true));

    let mut swarm = Swarm::new(transport, behaviour, local_peer_id);

    // Tell the swarm to listen on all interfaces and a random, OS-assigned port.
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    // Dial the peer identified by the multi-address given as the second command-line argument, if any.
    if let Some(addr) = std::env::args().nth(1) {
        let remote: Multiaddr = addr.parse()?;
        swarm.dial(remote)?;
        println!("Dialed {}", addr);
    }

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => println!("Listenting on {:?}", address),
            SwarmEvent::Behaviour(event) => println!("{:?}", event),
            _ => {}
        }
    }

}