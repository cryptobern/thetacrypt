use clap::Parser;
use log::{error, info};
use std::{path::PathBuf, process::exit};
use theta_network::{proxy::proxyp2p::ProxyConfig, types::message::NetMessage};
use theta_orchestration::{
    instance_manager::instance_manager::{InstanceManager, InstanceManagerCommand},
    key_manager::key_manager::{KeyManager, KeyManagerCommand},
};
use theta_schemes::keys::key_chain::KeyChain;
use theta_service::rpc_request_handler;
use utils::server::{cli::ServerCli, types::ServerProxyConfig};

#[tokio::main]
async fn main() {
    env_logger::init();

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
    let cfg = match ServerProxyConfig::from_file(&server_cli.config_file) {
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
pub async fn start_server(config: &ServerProxyConfig, keychain_path: PathBuf) {
    //Config for our proxy
    let net_config = ProxyConfig {
        listen_addr: config.get_listen_addr(),
        p2p_port: config.my_p2p_port(),
        proxy_addr: config.proxy_node_ip(),
    };

    // Network to protocol communication
    let (n2p_sender, n2p_receiver) = tokio::sync::mpsc::channel::<NetMessage>(32);

    // Protocol to network communication
    let (p2n_sender, p2n_receiver) = tokio::sync::mpsc::channel::<NetMessage>(32);

    let my_id = config.id;
    info!("Starting server with ID {}", my_id);

    info!(
        "Starting connection to the local instance of Tendermit to forward messages to the P2P network on {}",
        config.proxy_node_ip()
    );
    tokio::spawn(async move {
        theta_network::proxy::proxyp2p::init(p2n_receiver, n2p_sender, net_config, my_id).await;
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
            p2n_sender,
            n2p_receiver,
        );
        mfw.run().await;
    });

    let my_listen_address = config.listen_address.clone();
    let my_rpc_port = config.my_rpc_port();
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
