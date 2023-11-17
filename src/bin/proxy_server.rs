use clap::Parser;
use log::{error, info};
use std::process::exit;
use theta_events::event::emitter::start_null_emitter;
use theta_network::{proxy::proxyp2p::ProxyConfig, types::message::NetMessage};
use theta_orchestration::keychain::KeyChain;
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

    // Here we create an empty keychain and initialize it only if a key file has been provided
    let mut keychain = KeyChain::new();
    if server_cli.key_file.is_some() {
        keychain = match KeyChain::from_file(&server_cli.key_file.clone().unwrap()) {
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
pub async fn start_server(config: &ServerProxyConfig, keychain: KeyChain) {
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

    let my_listen_address = config.listen_address.clone();
    let my_rpc_port = config.my_rpc_port();
    info!(
        "Starting RPC server on {}:{}",
        my_listen_address, my_rpc_port
    );

    let (emitter_tx, emitter_shutdown_tx, emitter_handle) = start_null_emitter();
    let rpc_handle = tokio::spawn(async move {
        rpc_request_handler::init(
            my_listen_address,
            my_rpc_port.into(), // RPC handler expects u32, which makes little sense for a port
            keychain,
            n2p_receiver,
            p2n_sender,
            emitter_tx,
        )
        .await
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Threshold server received ctrl-c, shutting down");

            info!("Notifying event emitter of shutdown");
            emitter_shutdown_tx.send(true).unwrap();
            // Now that it's shutting down we can await its handle to ensure it has shut down.
            emitter_handle.await.unwrap().unwrap();

            info!("Killing RPC server");
            rpc_handle.abort();

            info!("Shutdown complete");
        }
    }
}
