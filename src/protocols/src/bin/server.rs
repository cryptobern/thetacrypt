use std::str::FromStr;
// use std::str::from_utf8;    
// use std::convert::TryInto;
// use std::thread::sleep;
use std::{env, result};
// use std::fs::{File, self};

use network::config::tendermint_net;
use network::config::static_net;
use network::types::message::P2pMessage;
use protocols::{rpc_request_handler, keychain::KeyChain};
use tokio::signal;

const TENDERMINT_CONFIG_PATH: &str = "../network/src/config/tendermint_net/config.toml";
const LOCAL_CONFIG_PATH: &str = "../network/src/config/static_net/config.toml";
// todo: Read from conf file
const RPC_DEFAULT_LISTEN_PORT: u32 = 50050;

#[tokio::main]
async fn main()  -> Result<(), Box<dyn std::error::Error>> {
    // Read configuration files
    let tendermint_config = tendermint_net::config_service::load_config(TENDERMINT_CONFIG_PATH.to_string());
    //let localnet_config = static_net::config_service::load_config(LOCAL_CONFIG_PATH.to_string());

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Please provide server ID.")
    }

    let my_id = u32::from_str(&args[1])?;

    let localnet_config = static_net::config_service::load_config(&my_id);
    let my_addr = tendermint_net::config_service::get_rpc_base_address(&tendermint_config);
    let mut my_port = tendermint_net::config_service::get_rpc_port(&tendermint_config);
    let my_keyfile = format!("conf/keys_{my_id}.json");
    
    println!(">> MAIN: Reading keys from keychain file: {}", my_keyfile);
    let key_chain: KeyChain = KeyChain::from_file(&my_keyfile)?; 

    // Create channel for sending P2P messages received at the network module to the protocols
    let (net_to_protocols_sender, net_to_protocols_receiver) = tokio::sync::mpsc::channel::<P2pMessage>(32);
    let net_to_protocols_sender2 = net_to_protocols_sender.clone(); //test

    // Create channel for sending P2P messages from a protocol to the network module
    let (protocols_to_net_sender, protocols_to_net_receiver) = tokio::sync::mpsc::channel::<P2pMessage>(32);


    // if "-l" is provided as cli argument we set up a local network
    if args.len() == 3 && args[2] == "-l" {
        println!(">> MAIN: Initiating LOCAL lib_P2P-based network instance.");
        my_port = static_net::config_service::get_rpc_port(&localnet_config, my_id);
        tokio::spawn(async move {
            network::p2p::gossipsub_setup::static_net::init(
                protocols_to_net_receiver,
                net_to_protocols_sender,
                localnet_config,
                my_id,
            ).await;
        });
    } else {
        println!(">> MAIN: Initiating lib_P2P-based network instance with TENDERMINT.");
        tokio::spawn(async move {
            network::p2p::gossipsub_setup::tendermint_net::init(
                protocols_to_net_receiver,
                net_to_protocols_sender,
                tendermint_config,
                my_id,
            ).await;
        });
    }

    // Read key file
    let my_keyfile = format!("conf/keys_{my_id}.json");
    println!(">> MAIN: Reading keys from keychain file: {}", my_keyfile);
    let key_chain: KeyChain = KeyChain::from_file(&my_keyfile)?; 

    // Start Rpc Request handler in a new thread
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

    // Wait until termination signal
    tokio::select! {
        _ = signal::ctrl_c() => {
            println!(">> MAIN: Terminating.");
            return Ok(());
        },
    }
    
    Ok(())
}   
