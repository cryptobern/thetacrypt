use std::{process::exit};
use log::{error, info};
use clap::Parser;

use network::{config::static_net, types::message::P2pMessage};

use protocols::{
    keychain::KeyChain,
    server::{types::ServerConfig, cli::ServerCli},
    rpc_request_handler,
};


#[tokio::main]
async fn main() {
    env_logger::init();

    let version = env!("CARGO_PKG_VERSION");
    info!("Starting server, version: {}", version);

    let server_cli = ServerCli::parse();

    info!(
        "Loading configuration from file: {}",
        server_cli.config_file
            .to_str()
            .unwrap_or("Unable to print path, was not valid UTF-8"),
    );
    let cfg = match ServerConfig::from_file(&server_cli.config_file) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("{}", e);
            exit(1);
        }
    };

    info!(
        "Loading keychain from file: {}",
        server_cli.key_file
            .to_str()
            .unwrap_or("Unable to print path, was not valid UTF-8")
    );
    let keychain = match KeyChain::from_file(&server_cli.key_file) {
        Ok(key_chain) => key_chain,
        Err(e) => {
            error!("{}", e);
            exit(1);
        }
    };

    start_server(&cfg, keychain).await;

    info!("Server is running");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received interrupt signal, shutting down");
            return;
        }
    }
}


/// Start main event loop of server.
pub async fn start_server(config: &ServerConfig, keychain: KeyChain) {
    // Build local-net config required by provided static-network implementation.
    let local_cfg = static_net::deserialize::Config {
        ids: config.peer_ids(),
        ips: config.peer_ips(),
        p2p_ports: config.peer_p2p_ports(),
        rpc_ports: config.peer_rpc_ports(),
        base_listen_address: format!("/ip4/{}/tcp/", config.listen_address),
    };

    let local_cfg2 = static_net::deserialize::Config {
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
        rpc_request_handler::init(
            my_listen_address,
            my_rpc_port,
            keychain,
            n2p_receiver,
            p2n_sender,
            n2p_sender_rpc,
            local_cfg2,
            my_id
        )
        .await
    });
}
