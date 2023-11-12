use clap::Parser;
use log::{error, info};
use log4rs;
use std::process::exit;
use theta_orchestration::keychain::KeyChain;
use theta_service::rpc_request_handler;
use utils::server::{cli::ServerCli, types::ServerConfig};

use theta_network::{config::static_net, types::message::NetMessage};

#[tokio::main]
async fn main() {
    log4rs::init_file("log4rs.yaml", Default::default()).unwrap();

    let version = env!("CARGO_PKG_VERSION");
    info!("Starting server, version: {}", version);

    let server_cli = ServerCli::parse();

    info!(
        "Loading configuration from file: {}",
        server_cli
            .config_file
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

    // Here we create an empty keychain and initialize it only if a key file has been provided
    let mut keychain = KeyChain::new();
    if server_cli.key_file.is_some() {
        keychain = match KeyChain::from_config_file(&server_cli.key_file.clone().unwrap()) {
            Ok(key_chain) => key_chain,
            Err(e) => {
                error!("{}", e);
                exit(1);
            }
        };

        info!(
            "Loading keychain from file: {}",
            server_cli
                .key_file
                .unwrap()
                .to_str()
                .unwrap_or("Unable to print path, was not valid UTF-8")
        );
    }

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
    let net_cfg = static_net::deserialize::Config {
        ids: config.peer_ids(),
        ips: config.peer_ips(),
        p2p_ports: config.peer_p2p_ports(),
        rpc_ports: config.peer_rpc_ports(),
        base_listen_address: format!("/ip4/{}/tcp/", config.listen_address),
    };

    // Network to protocol communication
    let (net_to_prot_sender, net_to_prot_receiver) = tokio::sync::mpsc::channel::<NetMessage>(32);

    // Protocol to network communication
    let (prot_to_net_sender, prot_to_net_receiver) = tokio::sync::mpsc::channel::<NetMessage>(32);

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
        theta_network::p2p::gossipsub_setup::static_net::init(
            prot_to_net_receiver,
            net_to_prot_sender,
            net_cfg,
            my_id,
        )
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
            net_to_prot_receiver,
            prot_to_net_sender,
        )
        .await
    });
}
