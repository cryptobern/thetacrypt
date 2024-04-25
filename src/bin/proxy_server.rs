use clap::Parser;
use log::{error, info};
use std::{path::PathBuf, process::exit};
use theta_events::event::emitter::{self, start_null_emitter};
use theta_network::{network_manager::{network_director::NetworkDirector, network_manager::NetworkManager, network_manager_builder::NetworkManagerBuilder}, p2p::gossipsub_setup::static_net::P2PComponent, proxy::proxyp2p::{ProxyConfig, ProxyP2PStub}, types::message::NetMessage};
use theta_orchestration::{
    instance_manager::instance_manager::{InstanceManager, InstanceManagerCommand},
    key_manager::key_manager::{KeyManager, KeyManagerCommand},
};
use log4rs;

use theta_service::rpc_request_handler;
use utils::server::{cli::ServerCli, types::ServerProxyConfig};

#[tokio::main]
async fn main() {

    // let version = env!("CARGO_PKG_VERSION");
    // info!("Starting server, version: {}", version);

    // let server_cli = ServerCli::parse();

    // log4rs::init_file(server_cli.log4rs_config, Default::default())
    // .expect("Unable to access supplied log4rs configuration file");

    // info!(
    //     "Loading configuration from file: {}",
    //     server_cli
    //         .config_file
    //         .to_str()
    //         .unwrap_or("Unable to print path, was not valid UTF-8"),
    // );
    // let cfg = match ServerProxyConfig::from_file(&server_cli.config_file) {
    //     Ok(cfg) => cfg,
    //     Err(e) => {
    //         error!("{}", e);
    //         exit(1);
    //     }
    // };

    // if server_cli.key_file.is_none() {
    //     error!("Please specify the keystore location");
    //     exit(-1);
    // }

    // let keychain_path = server_cli.key_file.unwrap();

    // info!("Keychain location: {}", keychain_path.display());

    // info!("Server is running");

    // start_server(&cfg, keychain_path).await;


}

//Start main event loop of server.
pub async fn start_server(config: &ServerProxyConfig, keychain_path: PathBuf) {
    // //Config for our proxy
    // let net_config = ProxyConfig {
    //     listen_addr: config.get_listen_addr(),
    //     p2p_port: config.my_p2p_port(),
    //     proxy_addr: config.proxy_node_ip(),
    //     proxy_port: config.proxy_node_port(),
    // };

    // // Network to protocol communication
    // let (n2p_sender, n2p_receiver) = tokio::sync::mpsc::channel::<NetMessage>(32);

    // // Protocol to network communication
    // let (p2n_sender, p2n_receiver) = tokio::sync::mpsc::channel::<NetMessage>(32);

    // let my_id = config.id;
    // info!("Starting server with ID {}", my_id);

    // info!(
    //     "Starting connection to the local instance of the target platform forward messages to the P2P network on {}",
    //     config.proxy_node_ip()
    // );

    // // Setting up the network 
    // // Instantiate the p2p component implementation
    // let mut p2p_proxy = ProxyP2PStub::new(net_config, my_id);

    // p2p_proxy.init().await;

    // let mut network_builder = NetworkManagerBuilder::default();
    // network_builder.set_outgoing_msg_receiver(p2n_receiver);
    // network_builder.set_incoming_message_sender(n2p_sender);
    // network_builder.set_config(net_config.clone());
    // network_builder.set_id(my_id);
    // NetworkDirector::construct_standalone_network(&mut network_builder, config.clone(), my_id).await;

    // // Instantiate the NetworkManager
    // let mut network_manager = network_builder.build();

    // tokio::spawn(async move {
    //     network_manager.run()
    //     .await;
    // });

    // // Channel to send commands to the KeyManager.
    // // Used by the InstanceManager and RpcRequestHandler
    // // The channel is owned by the server and must never be closed.
    // let (key_manager_command_sender, key_manager_command_receiver) =
    //     tokio::sync::mpsc::channel::<KeyManagerCommand>(32);

    // info!("Initiating the key manager.");
    // tokio::spawn(async move {
    //     let mut sm = KeyManager::new(keychain_path, key_manager_command_receiver);
    //     sm.run().await;
    // });

    // /* Starting instance manager */
    // // Channel to send commands to the InstanceManager.
    // // The sender end is owned by the server and must never be closed.
    // let (instance_manager_sender, instance_manager_receiver) =
    //     tokio::sync::mpsc::channel::<InstanceManagerCommand>(32);

    // // Spawn InstanceManager
    // // Takes ownership of instance_manager_receiver, incoming_message_receiver, state_command_sender
    // info!("Initiating InstanceManager.");

    // let (emitter_tx, _emitter_shutdown_tx, _emitter_handle) = match &config.event_file {
    //     Some(f) => {
    //         info!(
    //             "Starting event emitter with output file {}",
    //             f.to_str().unwrap_or("<cannot print path>")
    //         );
    //         let emitter = emitter::new(&f);

    //         emitter::start(emitter)
    //     }
    //     None => {
    //         info!("Starting null-emitter, which will discard all benchmarking events");

    //         start_null_emitter()
    //     }
    // };

    // let inst_cmd_sender = instance_manager_sender.clone();
    // let key_mgr_sender = key_manager_command_sender.clone();

    // let emitter_tx2 = emitter_tx.clone();

    // tokio::spawn(async move {
    //     let mut mfw = InstanceManager::new(
    //         key_mgr_sender,
    //         instance_manager_receiver,
    //         inst_cmd_sender,
    //         p2n_sender,
    //         n2p_receiver,
    //         emitter_tx,
    //     );
    //     mfw.run().await;
    // });

    // let my_listen_address = config.listen_address.clone();
    // let my_rpc_port = config.my_rpc_port();
    // info!(
    //     "Starting RPC server on {}:{}",
    //     my_listen_address, my_rpc_port
    // );

    // let (_emitter_tx, emitter_shutdown_tx, emitter_handle) = start_null_emitter();
    // let rpc_handle = tokio::spawn(async move {
    //     rpc_request_handler::init(
    //         my_listen_address,
    //         my_rpc_port,
    //         instance_manager_sender,
    //         key_manager_command_sender,
    //         emitter_tx2,
    //     )
    //     .await
    // });

    // tokio::select! {
    //     _ = tokio::signal::ctrl_c() => {
    //         info!("Threshold server received ctrl-c, shutting down");

    //         info!("Notifying event emitter of shutdown");
    //         emitter_shutdown_tx.send(true).unwrap();
    //         // Now that it's shutting down we can await its handle to ensure it has shut down.
    //         emitter_handle.await.unwrap().unwrap();

    //         info!("Killing RPC server");
    //         rpc_handle.abort();

    //         info!("Shutdown complete");
    //     }
    // }
}
