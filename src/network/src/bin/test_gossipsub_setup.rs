use std::env;
use network::types::message::P2pMessage;
use network::config::localnet_config;
use std::time::Duration;
use tokio::time;
use std::str::FromStr;

const LOCAL_CONFIG_PATH: &str = "src/config/localnet_config/config.toml";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Read configuration file and key file
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Please provide server ID.")
    }
    let my_id = u32::from_str(&args[1])?;
    let my_keyfile = format!("conf/keys_{my_id}.json");
    println!(">> TEST: Reading keys from keychain file: {}", my_keyfile);
    // let key_chain: KeyChain = KeyChain::from_file(&my_keyfile);

    let localnet_config = localnet_config::config_service::load_config(LOCAL_CONFIG_PATH.to_string());

    // Create channel for sending P2P messages received at the network module to the protocols
    let (net_to_protocols_sender, mut net_to_protocols_receiver) = tokio::sync::mpsc::channel::<P2pMessage>(32);
    let net_to_protocols_sender2 = net_to_protocols_sender.clone(); //test

    // Create channel for sending P2P messages from a protocol to the network module
    let (protocols_to_net_sender, mut protocols_to_net_receiver) = tokio::sync::mpsc::channel::<P2pMessage>(32);

    // // sends a Vec<u8> into the channel as spawned thread
    tokio::spawn(async move {
        // test vector
        // let my_vec: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
        // let my_msg = P2pMessage { instance_id: 1.to_string(), message_data: my_vec };
        // repeated sending in endless loop for testing purpose
        for count in 0..5 {
            // waits for sending the next message
            time::sleep(Duration::from_millis(10000)).await;
            let mut my_vec: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
            
            // my_vec[0] = count; // to keep track of the messages
            my_vec[1] = rand::random(); // to prevent dublicate messages
            let my_msg = P2pMessage { instance_id: 1.to_string(), message_data: my_vec };
            // sends Vec<u8> into the channel
            // chn_out_send.send(my_vec.to_vec()).unwrap();
            // my_msg = P2pMessage {instance_id: 1.to_string(), message_data: my_vec };
            println!(">> TEST: SEND ->: {:?}", my_msg);
            match protocols_to_net_sender.send(my_msg).await {
                Ok(_) => (),
                Err(e) => println!(">> TEST: send to channel error: {e}"),
            };
            // protocols_to_net_sender.send(my_msg).await.unwrap();
        }
        // TODO: close channel?
        // println!(">> TEST: closing channel");
        // protocols_to_net_sender.closed().await;
    });

    // Start the network
    println!(">> TEST: Initiating lib_P2P-based network instance.");
    tokio::spawn(async move {
        network::p2p::gossipsub::localnet_setup::init(
            protocols_to_net_receiver,
            net_to_protocols_sender,
            localnet_config,
            my_id
        ).await;
    });
    
    // receive incoming messages via the internal channel
    Ok(while let Some(message) = net_to_protocols_receiver.recv().await {
        println!(">> TEST: RECV <-: {:?}", message);
    })
}
