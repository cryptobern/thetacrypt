use libp2p::gossipsub::{IdentTopic as GossibsubTopic};
use libp2p::Multiaddr;
use network::setup::gossipsub_setup::init;

#[tokio::main]
async fn main() {
    // Create a Gossipsub topic
    let topic = GossibsubTopic::new("gossipsub p2p");
    
    // TODO: get listener address from tendermint RPC endpoint
    let base_listen_addr = "/ip4/0.0.0.0/tcp/";
    let base_dial_addr = "/ip4/127.0.0.1/tcp/";
    
    // get listen_address from first cli argument and dial_address from second cli argument
    if let Some(listen_on) = std::env::args().nth(1) {
        let listen_address = format!("{}{}", base_listen_addr, listen_on);

        // get peer address to dial from second cli
        if let Some(dial_to) = std::env::args().nth(2) {
            let dial = format!("{}{}", base_dial_addr, dial_to);
            let dial_address: Multiaddr = dial.parse().expect("User to provide valid address.");
            // setup swarm and listener, connect to another peer and kick off event loop
            init(topic, listen_address.parse().unwrap(), dial_address).await;
        } else {
            println!("provide peer-address to connect with.");
        }
    }

    // // specify peer address to dial (now: command line parameter)
    // if let Some(to_dial) = std::env::args().nth(2) {
    //     let dial_address: Multiaddr = to_dial.parse().expect("User to provide valid address.");
    //     init(topic, listen_address.to_string(), dial_address).await;
    // } else {
    //     println!("provide peer-address to connect with.");
    // }
}