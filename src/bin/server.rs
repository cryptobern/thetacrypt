use clap::Parser;
use futures::SinkExt;
use log::{debug, error, info, warn};
use log4rs;
use sha2::{Digest, Sha256};
use tokio::{runtime::Handle, sync::Notify, task::JoinHandle};
use std::{future, path::PathBuf, process::exit, result, sync::Arc, vec};
use theta_events::event::emitter::{self, start_null_emitter};
use theta_orchestration::{
    instance_manager::instance_manager::{InstanceManager, InstanceManagerCommand},
    key_manager::key_manager::{KeyManager, KeyManagerCommand},
};
use theta_service::rpc_request_handler;

use utils::server::{cli::ServerCli, types::ServerConfig};

use theta_network::{
    network_manager::{network_director::NetworkDirector, network_manager_builder::NetworkManagerBuilder}, types::{config::NetworkConfig, message::NetMessage}
};


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

    //TODO: Move cjhecking existance of emmitter file path also here and return error if it does not exist

    //Logic for handling correctly the shutdown of the server
    let shutdown_notify = Arc::new(Notify::new());
    let mut handles: Vec<JoinHandle<Result<(), String>>> = vec![];

    // Starting all the component of the server. Here we want to return a list of handles for every component
    let result = start_server(&cfg, keychain_path, shutdown_notify.clone());
    match result {
        Ok(h) => handles = h,
        Err(e) => {
            error!("Failed to start server: {}", e);
            //Notify the already started components to shut down
            shutdown_notify.notify_waiters();
        }
    }
    
    // TODO: Handle shutdown gracefully in the main thread.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Threshold server received ctrl-c, shutting down");
        }
        _ = monitor_for_task_failure(&mut handles) => {
            warn!("A task failed, shutting down");
        }
    }

    info!("Notifying all components of shutdown");
    shutdown_notify.notify_waiters();

    info!("Waiting for all components to shut down");
    for handle in handles {
        let _ = handle.await; //Here additionally we could check if the result is an error, even though we are shutting down anyway
    }

    info!("Shutdown complete");
    
}

async fn monitor_for_task_failure(handles: &mut Vec<JoinHandle<Result<(), String>>>) {

    info!("Monitoring for task failure");

    //monitor the tasks and return as soon as one of them finishes
    let result = futures::future::select_all(handles.iter_mut()).await;

    let (handle_ready, index, _) = result;

    // If the handle is ready, then it means that the task has finished
    if handle_ready.is_ok() {
        match handle_ready.unwrap() {
            Ok(_) => {
                info!("Task {} finished successfully", index);
            }
            Err(e) => {
                error!("Task {} failed: {}", index, e);
            }
        }

        // Remove the handle from the list
        handles.remove(index);
    } else {
        error!("Error during join: {:?}", handle_ready.err().unwrap());
    }
}

/// Start main event loop of server.
pub fn start_server(config: &ServerConfig, keychain_path: PathBuf, shutdown_notify: Arc<Notify>) -> Result<Vec<JoinHandle<Result<(), String>>>, String >{

    let mut handles = vec![];

    let try_network_config = NetworkConfig::new(config);

    if try_network_config.is_err(){
        return Err(try_network_config.err().unwrap())
    } 

    let net_cfg =try_network_config.unwrap();

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

    //Here introduce code to differenciate between standalone and blockchain integration
    if config.proxy_node.is_some(){
        NetworkDirector::construct_proxy_network(&mut network_builder, net_cfg.clone(), my_id);
    }else{
        NetworkDirector::construct_standalone_network(&mut network_builder, net_cfg.clone(), my_id);
    }

    // Instantiate the NetworkManager
    let mut network_manager = network_builder.build();
    let shutdown_network = shutdown_notify.clone();
    let network_handle = tokio::spawn(async move {
        return network_manager.run(shutdown_network).await;
    });

    handles.push(network_handle);

    // Channel to send commands to the KeyManager.
    // Used by the InstanceManager and RpcRequestHandler
    // The channel is owned by the server and must never be closed.
    let (key_manager_command_sender, key_manager_command_receiver) =
        tokio::sync::mpsc::channel::<KeyManagerCommand>(32);

    info!("Initiating the key manager.");
    let shutdown_key_manager = shutdown_notify.clone();
    let key_manager_handle = tokio::spawn(async move {
        let mut sm = KeyManager::new(keychain_path, key_manager_command_receiver);
        return sm.run(shutdown_key_manager).await;
    });

    handles.push(key_manager_handle);

    /* Starting instance manager */
    // Channel to send commands to the InstanceManager.
    // The sender end is owned by the server and must never be closed.
    let (instance_manager_sender, instance_manager_receiver) =
        tokio::sync::mpsc::channel::<InstanceManagerCommand>(32);

    // Spawn InstanceManager
    // Takes ownership of instance_manager_receiver, incoming_message_receiver, state_command_sender
    info!("Initiating InstanceManager.");

    //TODO: Handle also here the life-cycle of the emitter
    let (emitter_tx, emitter_handle) = match &config.event_file {
        Some(f) => {
            info!(
                "Starting event emitter with output file {}",
                f.to_str().unwrap_or("<cannot print path>")
            );
            let emitter = emitter::new(&f);

            let result = emitter::start(emitter, shutdown_notify.clone());
            match result {
                Ok((tx, handle)) => (tx, handle),
                Err(e) => {
                    error!("Failed to start event emitter: {}", e);
                    return Err("Failed to start event emitter".to_string());
                }
            }
        }
        None => {
            info!("Starting null-emitter, which will discard all benchmarking events");

            start_null_emitter(shutdown_notify.clone())
        }
    };

    handles.push(emitter_handle);

    let inst_cmd_sender = instance_manager_sender.clone();
    let key_mgr_sender = key_manager_command_sender.clone();

    let emitter_tx2 = emitter_tx.clone();

    let shutdown_instance_manager = shutdown_notify.clone();
    let instance_manager_handle = tokio::spawn(async move {
        let mut mfw = InstanceManager::new(
            key_mgr_sender,
            instance_manager_receiver,
            inst_cmd_sender,
            prot_to_net_sender,
            net_to_prot_receiver,
            emitter_tx,
        );
        return mfw.run(shutdown_instance_manager).await;
    });

    handles.push(instance_manager_handle);

    let my_listen_address = config.listen_address.clone();
    let my_rpc_port = config.rpc_port;
    info!(
        "Starting RPC server on {}:{}",
        my_listen_address, my_rpc_port
    );
    let shutdown_rpc_handler = shutdown_notify.clone();
    let rpc_handle = tokio::spawn(async move {
        rpc_request_handler::init(
            my_listen_address,
            my_rpc_port,
            instance_manager_sender,
            key_manager_command_sender,
            emitter_tx2,
            shutdown_rpc_handler
        )
        .await
    });

    handles.push(rpc_handle);

    return Ok(handles);
}
