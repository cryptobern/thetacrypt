use clap::Parser;
use log::{error, info};
use log4rs;
use std::{path::PathBuf, process::exit};
use theta_orchestration::{
    instance_manager::instance_manager::{InstanceManager, InstanceManagerCommand},
    key_manager::key_manager::{KeyManager, KeyManagerCommand},
};
use theta_service::rpc_request_handler;
use tonic::server;
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

    if server_cli.key_file.is_none() {
        error!("Please specify the keychain location");
        exit(-1);
    }

    let keychain_path = server_cli.key_file.unwrap();

    info!("Keychain location: {}", keychain_path.display());

    start_server(&cfg, keychain_path).await;

    info!("Server is running");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received interrupt signal, shutting down");
            return;
        }
    }
}

/// Start main event loop of server.
pub async fn start_server(config: &ServerConfig, keychain_path: PathBuf) {
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

    // Channel to send commands to the KeyManager.
    // Used by the InstanceManager and RpcRequestHandler
    // The channel is owned by the server and must never be closed.
    let (key_manager_command_sender, key_manager_command_receiver) =
        tokio::sync::mpsc::channel::<KeyManagerCommand>(32);

    info!("Initiating the key manager.");
    tokio::spawn(async move {
        let mut sm = KeyManager::new(keychain_path, key_manager_command_receiver);
        sm.run().await;
    });

    /* Starting instance manager */
    // Channel to send commands to the InstanceManager.
    // The sender end is owned by the server and must never be closed.
    let (instance_manager_sender, instance_manager_receiver) =
        tokio::sync::mpsc::channel::<InstanceManagerCommand>(32);

    // Spawn InstanceManager
    // Takes ownership of instance_manager_receiver, incoming_message_receiver, state_command_sender
    info!("Initiating InstanceManager.");

    let inst_cmd_sender = instance_manager_sender.clone();
    let key_mgr_sender = key_manager_command_sender.clone();

    tokio::spawn(async move {
        let mut mfw = InstanceManager::new(
            key_mgr_sender,
            instance_manager_receiver,
            inst_cmd_sender,
            prot_to_net_sender,
            net_to_prot_receiver,
        );
        mfw.run().await;
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
            instance_manager_sender,
            key_manager_command_sender,
        )
        .await
    });
}
