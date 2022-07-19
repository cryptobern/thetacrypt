use std::str::FromStr;
use std::str::from_utf8;    
use std::convert::TryInto;
use std::thread::sleep;
use std::{env, result};
use std::fs::{File, self};

use network::config::tendermint_net_config::config_service::load_config;
use network::types::message::P2pMessage;
use protocols::{rpc_request_handler, keychain::KeyChain};
use tokio::signal;

const RPC_DEFAULT_LISTEN_PORT: u32 = 50050; // for local network
const TENDERMINT_CONFIG_PATH: &str = "../network/src/config/tendermint_net_config/config.toml";

#[tokio::main]
async fn main()  -> Result<(), Box<dyn std::error::Error>> {
    // Read configuration file and key file
    let tendermint_config = load_config(TENDERMINT_CONFIG_PATH.to_string());

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Please provide server ID.")
    }
    let my_id = u32::from_str(&args[1])?; // for local network
    let my_port = RPC_DEFAULT_LISTEN_PORT + my_id; // for local network
    // let my_port = tendermint_config.rpc_port; // for docker environment
    let my_addr = tendermint_config.rpc_base_listen_address;
    let my_keyfile = format!("conf/keys_{my_id}.json");
    println!(">> MAIN: Reading keys from keychain file: {}", my_keyfile);
    let key_chain: KeyChain = KeyChain::from_file(&my_keyfile); 

    // Create channel for sending P2P messages received at the network module to the protocols
    let (net_to_protocols_sender, net_to_protocols_receiver) = tokio::sync::mpsc::channel::<P2pMessage>(32);
    let net_to_protocols_sender2 = net_to_protocols_sender.clone(); //test

    // Create channel for sending P2P messages from a protocol to the network module
    let (protocols_to_net_sender, mut protocols_to_net_receiver) = tokio::sync::mpsc::channel::<P2pMessage>(32);

   
    
    // Start the network
    println!(">> MAIN: Initiating lib_P2P-based network instance.");
    tokio::spawn(async move {
        network::p2p::gossipsub::setup::init(protocols_to_net_receiver,
                                            net_to_protocols_sender,
                                            my_id,
                                            )
                                            .await;
    });
    // tokio::spawn(async move {
    //     network::p2p::gossipsub::tendermint_setup::init(protocols_to_net_receiver,
    //                                         net_to_protocols_sender,
    //                                         )
    //                                         .await;
    // });

    println!(">> MAIN: Starting the RPC request handler.");
    tokio::spawn(async move {
        rpc_request_handler::init(
            my_addr,
            my_port.into(),
            key_chain,
            net_to_protocols_receiver,
            protocols_to_net_sender,
            net_to_protocols_sender2,
        ).await;
    });

    //  let rt = tokio::runtime::Builder::new_multi_thread()
    //     .enable_all()
    //     .build()
    //     .unwrap()
    //     .block_on(async {
    //         rpc_request_handler::init(
    //             my_addr,
    //             my_port,
    //             key_chain,
    //             net_to_protocols_receiver,
    //             protocols_to_net_sender,
    //             net_to_protocols_sender2,
    //         ).await;
    // });

    tokio::select! {
        _ = signal::ctrl_c() => {},
    }
    
    Ok(())
}   