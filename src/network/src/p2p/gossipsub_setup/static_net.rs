use futures::prelude::*;
use libp2p::{
    gossipsub::{Gossipsub, IdentTopic as GossibsubTopic},
    identity,
    swarm::SwarmEvent,
    PeerId, Swarm,
};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::config::static_net::{config_service::*, deserialize::Config};
use crate::types::message::P2pMessage;

use super::net_utils::*;

pub async fn init(
    outgoing_msg_receiver: Receiver<P2pMessage>,
    incoming_msg_sender: Sender<P2pMessage>,
    localnet_config: Config,
    my_id: u32,
) {
    // Create a Gossipsub topic
    let topic: GossibsubTopic = GossibsubTopic::new("gossipsub broadcast");

    // Create a random Keypair and PeerId (hash of the public key)
    let id_keys = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(id_keys.public());
    // println!(">> NET: Local peer id: {:?}", local_peer_id);

    // Create a keypair for authenticated encryption of the transport.
    let noise_keys = create_noise_keys(&id_keys);

    // Create a tokio-based TCP transport, use noise for authenticated
    // encryption and Mplex for multiplexing of substreams on a TCP stream.
    let transport = create_tcp_transport(noise_keys);

    // Create a Swarm to manage peers and events.
    let mut swarm = create_gossipsub_swarm(&topic, id_keys.clone(), transport, local_peer_id);

    // load listener address from config file
    let listen_addr = get_p2p_listen_addr(&localnet_config, my_id);
    println!(">> NET: Listening for P2P on: {}", listen_addr);

    // bind port to listener address
    match swarm.listen_on(listen_addr.clone()) {
        Ok(_) => (),
        Err(error) => println!(">> NET: listen {:?} failed: {:?}", listen_addr, error),
    }

    // dial another peer in the network
    dial_local_net(&mut swarm, localnet_config, my_id).await;

    // kick off tokio::select event loop to handle events
    run_event_loop(
        &mut swarm,
        topic,
        outgoing_msg_receiver,
        incoming_msg_sender,
    )
    .await;
}

// dial a peer in the local network, if it fails, retry another peer
async fn dial_local_net(swarm: &mut Swarm<Gossipsub>, config: Config, my_id: u32) {
    let mut index = 0;
    let n = config.ids.len();

    loop {
        let p_id = config.ids[index];
        if p_id == my_id {
            index = (index + 1) % n;
            continue; // don't dial own address
        } else {
            let dial_addr = get_dial_addr(&config, p_id);
            match swarm.dial(dial_addr.clone()) {
                Ok(_) => {
                    // println!(">> NET: Dialed {:?}", dial_addr);
                    match swarm.select_next_some().await {
                        SwarmEvent::ConnectionEstablished { endpoint, .. } => {
                            println!();
                            // wrong output --> might display dial_addr from a node that is not running yet!
                            // println!(">> NET: Connected to dial_addr: {:?}", dial_addr);

                            // only useful output when the endpoint is of Enum variant "Dialer".
                            // from https://docs.rs/libp2p/latest/libp2p/core/enum.ConnectedPoint.html:
                            // "For Dialer, this returns address. For Listener, this returns send_back_addr."
                            println!(
                                ">> NET: Connected to endpoint: {:?}",
                                endpoint.get_remote_address()
                            );
                            println!(">> NET: Ready for client requests ...");
                            break;
                        }
                        SwarmEvent::OutgoingConnectionError { .. } => {
                            index = (index + 1) % n; // try next peer address in next iteration

                            println!(">> NET: Connection to {dial_addr} NOT successful. Retrying in 2 sec.");
                            tokio::time::sleep(Duration::from_millis(2000)).await;
                        }
                        _ => {}
                    }
                }
                Err(e) => println!(">> NET: Dial {:?} failed: {:?}", dial_addr, e),
            };
        }
    }
}