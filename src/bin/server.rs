use clap::Parser;
use log::{error, info};
use log4rs;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, process::exit};
use theta_events::event::emitter::{self, start_null_emitter};
use theta_orchestration::{
    instance_manager::instance_manager::{InstanceManager, InstanceManagerCommand},
    key_manager::key_manager::{KeyManager, KeyManagerCommand},
};
use theta_service::rpc_request_handler;

use utils::server::{cli::ServerCli, types::ServerConfig};

use theta_network::{
    config::static_net, 
    network_manager::{network_director::NetworkDirector, network_manager::NetworkManager, network_manager_builder::NetworkManagerBuilder}, 
    p2p::gossipsub_setup::static_net::P2PComponent, 
    types::message::NetMessage,
    interface::TOB,
};
use tonic::async_trait;

#[tokio::main]
async fn main() {
    let server_cli = ServerCli::parse();

    log4rs::init_file(server_cli.log4rs_config, Default::default())
        .expect("Unable to access supplied log4rs configuration file");

    let version = env!("CARGO_PKG_VERSION");
    info!("Starting server, version: {}", version);

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

    if server_cli.key_file.is_none() { //TODO: thre should be a way to start everything without keys (maybe this is just for file location and it can be empty?)
        error!("Please specify the keystore location");
        exit(-1);
    }

    let keychain_path = server_cli.key_file.unwrap();

    info!("Keychain location: {}", keychain_path.display());

    start_server(&cfg, keychain_path).await;
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

    // TODO: Here we can have an init() function for the network (that gives back the id) 
    // and then a run() function to run it on a different thread


    let mut network_builder = NetworkManagerBuilder::default();
    network_builder.set_outgoing_msg_receiver(prot_to_net_receiver);
    network_builder.set_incoming_message_sender(net_to_prot_sender);
    network_builder.set_config(net_cfg.clone());
    network_builder.set_id(my_id);
    NetworkDirector::construct_standalone_network(&mut network_builder, net_cfg.clone(), my_id).await;

    // Instantiate the NetworkManager
    let mut network_manager = network_builder.build();

    tokio::spawn(async move {
        network_manager.run()
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

    let (emitter_tx, emitter_shutdown_tx, emitter_handle) = match &config.event_file {
        Some(f) => {
            info!(
                "Starting event emitter with output file {}",
                f.to_str().unwrap_or("<cannot print path>")
            );
            let emitter = emitter::new(&f);

            emitter::start(emitter)
        }
        None => {
            info!("Starting null-emitter, which will discard all benchmarking events");

            start_null_emitter()
        }
    };

    let inst_cmd_sender = instance_manager_sender.clone();
    let key_mgr_sender = key_manager_command_sender.clone();

    let emitter_tx2 = emitter_tx.clone();
    tokio::spawn(async move {
        let mut mfw = InstanceManager::new(
            key_mgr_sender,
            instance_manager_receiver,
            inst_cmd_sender,
            prot_to_net_sender,
            net_to_prot_receiver,
            emitter_tx,
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
    let rpc_handle = tokio::spawn(async move {
        rpc_request_handler::init(
            my_listen_address,
            my_rpc_port,
            instance_manager_sender,
            key_manager_command_sender,
            emitter_tx2,
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
