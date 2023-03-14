use futures::prelude::*;
use libp2p::{
    gossipsub::{Gossipsub, IdentTopic as GossibsubTopic},
    identity,
    swarm::SwarmEvent,
    PeerId, Swarm,
};
use log::{debug, info};

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
    debug!("NET: Listening for P2P on: {}", listen_addr);

    // bind port to listener address
    match swarm.listen_on(listen_addr.clone()) {
        Ok(_) => (),
        Err(error) => debug!("NET: listen {:?} failed: {:?}", listen_addr, error),
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

/// Dial all peers, and wait for at least one connection to be established.
///
/// Dialing all peers will let the underlying gossipsub network know of their existence, thus
/// allowing it to build up its mesh network.
async fn dial_local_net(swarm: &mut Swarm<Gossipsub>, config: Config, my_id: u32) {
    // Start by dialing all peers other than ourselves, letting the underlying network layer know
    // of their existenec, allowing it to connect if required.
    for peer_id in &config.ids {
        if *peer_id == my_id {
            // Let's not dial ourselves.
            continue;
        }

        let dial_addr = get_dial_addr(&config, *peer_id);
        // Note that the dial() method will *not* erorr if connection fails - e.g. dialing a
        // not-yet-reachable peer will work just fine. I assume it will rather fail if the thing we
        // pass is not actually dial-able - e.g. an invalid IP, or a peer ID of a peer we do not
        // know of.
        // As such, .dial() seems to just be a way to let the network layer know of peers which
        // exist, so it can try to connect to them.
        match swarm.dial(dial_addr.clone()) {
            Ok(_) => {}
            Err(e) => debug!("NET: Dial {:?} failed: {:?}", dial_addr, e),
        };
    }

    debug!("NET: Waiting for connection to first peer");
    // Now we wait until we've successfully connected to at least one peer.
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished { endpoint, .. } => {
                debug!(
                    "NET: Successfully connected to first peer on: {:?}",
                    endpoint.get_remote_address()
                );
                info!("NET: Ready for client requests...");
                break;
            }
            _ => {}
        }
    }
}
