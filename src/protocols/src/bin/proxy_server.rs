use std::{process::exit};
use log::{error, info};
use clap::Parser;

use network::{proxy::proxy::ProxyConfig, types::message::NetMessage};

use protocols::{
    keychain::KeyChain,
    server::{types::ServerProxyConfig, cli::ServerCli},
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
    let cfg = match ServerProxyConfig::from_file(&server_cli.config_file) {
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
pub async fn start_server(config: &ServerProxyConfig, keychain: KeyChain) {
    
    //Config for our proxy
    let net_config = ProxyConfig{
        listen_addr: config.get_listen_addr(),
        p2p_port: config.my_p2p_port(),
        proxy_addr: config.proxy_node_ip(),
    };


    // Network to protocol communication
    let (n2p_sender, n2p_receiver) = tokio::sync::mpsc::channel::<NetMessage>(32);
    // And a dedicated  copy for the RPC server
    let n2p_sender_rpc = n2p_sender.clone();

    // Protocol to network communication
    let (p2n_sender, p2n_receiver) = tokio::sync::mpsc::channel::<NetMessage>(32);

    let my_id = config.id;
    info!("Starting server with ID {}", my_id);

    info!(
        "Starting connection to the local instance of Tendermit to forward messages to the P2P network on {}",
        config.proxy_node_ip()
    );
    tokio::spawn(async move {
        network::proxy::proxy::init(p2n_receiver, n2p_sender, net_config, my_id)
            .await;
    });

    let my_listen_address = config.listen_address.clone();
    let my_rpc_port = config.my_rpc_port();
    info!(
        "Starting RPC server on {}:{}",
        my_listen_address, my_rpc_port
    );
    // tokio::spawn(async move {
    //     rpc_request_handler::init(
    //         my_listen_address,
    //         my_rpc_port.into(), // RPC handler expects u32, which makes little sense for a port
    //         keychain,
    //         n2p_receiver,
    //         p2n_sender,
    //         n2p_sender_rpc,
    //     )
    //     .await
    // });
}
