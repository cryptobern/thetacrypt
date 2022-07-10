use std::str::FromStr;
use std::str::from_utf8;    
use std::convert::TryInto;
use std::{env, result};
use std::fs::{File, self};

use network::p2p::gossipsub::setup::P2pMessage;
use protocols::{rpc_request_handler, keychain::KeyChain};

const RPC_DEFAULT_LISTEN_PORT: u32 = 50050;

fn main()  -> Result<(), Box<dyn std::error::Error>> {
    // Read configuration file and key file
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Please provide server ID.")
    }
    let my_id = u32::from_str(&args[1])?;
    let my_port = RPC_DEFAULT_LISTEN_PORT + my_id;
    let my_addr = String::from("::1");
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
                                         true,
                                                  my_id,
                                                4).await;
    });

    // Start the Rpc request handler
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            rpc_request_handler::init(
                my_addr,
                my_port,
                key_chain,
                net_to_protocols_receiver,
                protocols_to_net_sender,
                net_to_protocols_sender2,
            ).await;
        });
    
        Ok(())
}   