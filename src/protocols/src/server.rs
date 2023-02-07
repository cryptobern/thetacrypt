use log::info;
use network::{config::static_net, types::message::P2pMessage};

use crate::keychain::KeyChain;

pub mod cli;
pub mod config;

/// Start main event loop of server.
pub async fn start_server(config: &config::Config, keychain: KeyChain) {
    // Build local-net config required by provided static-network implementation.
    let local_cfg = static_net::deserialize::Config {
        ids: config.peer_ids(),
        ips: config.peer_ips(),
        p2p_ports: config.peer_p2p_ports(),
        rpc_ports: config.peer_rpc_ports(),
        base_listen_address: format!("/ip4/{}/tcp/", config.listen_address),
    };

    // Network to protocol communication
    let (n2p_sender, n2p_receiver) = tokio::sync::mpsc::channel::<P2pMessage>(32);
    // And a dedicated  copy for the RPC server
    let n2p_sender_rpc = n2p_sender.clone();

    // Protocol to network communication
    let (p2n_sender, p2n_receiver) = tokio::sync::mpsc::channel::<P2pMessage>(32);

    let my_id = config.id;
    info!("Starting server with ID {}", my_id);

    let my_p2p_port = match config.my_p2p_port() {
        Ok(port) => port,
        Err(e) => panic!("{}", e),
    };
    info!(
        "Starting Gossipsub P2P network on {}:{}",
        config.listen_address, my_p2p_port
    );
    tokio::spawn(async move {
        network::p2p::gossipsub_setup::static_net::init(p2n_receiver, n2p_sender, local_cfg, my_id)
            .await;
    });

    let my_listen_address = config.listen_address.clone();
    let my_rpc_port = match config.my_rpc_port() {
        Ok(port) => port,
        Err(e) => panic!("{}", e),
    };
    info!(
        "Starting RPC server on {}:{}",
        my_listen_address, my_rpc_port
    );
    tokio::spawn(async move {
        crate::rpc_request_handler::init(
            my_listen_address,
            my_rpc_port.into(), // RPC handler expects u32, which makes little sense for a port
            keychain,
            n2p_receiver,
            p2n_sender,
            n2p_sender_rpc,
        )
        .await
    });
}
