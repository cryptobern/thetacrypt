use network::types::message::P2pMessage;
use std::time::Duration;
use tokio::time;

use network::config::tendermint_net;

const TENDERMINT_CONFIG_PATH: &str = "/src/config/tendermint_config/config.toml";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let tendermint_config = tendermint_net::config_service::load_config(TENDERMINT_CONFIG_PATH.to_string());

    // Create channel for sending P2P messages received at the network module to the protocols
    let (net_to_protocols_sender, mut net_to_protocols_receiver) = tokio::sync::mpsc::channel::<P2pMessage>(32);

    // Create channel for sending P2P messages from a protocol to the network module
    let (protocols_to_net_sender, protocols_to_net_receiver) = tokio::sync::mpsc::channel::<P2pMessage>(32);

    // // sends a Vec<u8> into the channel as spawned thread
    tokio::spawn(async move {
        // repeated sending in loop for testing purpose
        for count in 0.. {
            // waits for sending the next message
            time::sleep(Duration::from_millis(20000)).await;

            // test vector
            let mut my_vec: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
            my_vec[0] = count; // to keep track of the messages
            my_vec[1] = rand::random(); // to prevent dublicate messages
            let peer_id = tendermint_net::config_service::get_tendermint_node_id().await;
            // test msg
            let my_msg = P2pMessage { instance_id: peer_id, message_data: my_vec };
            
            // sends msg into the channel
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
        network::p2p::gossipsub_setup::tendermint_net::init(
            protocols_to_net_receiver,
            net_to_protocols_sender,
            tendermint_config
        ).await;
    });
    
    // receive incoming messages via the internal channel
    Ok(while let Some(message) = net_to_protocols_receiver.recv().await {
        println!(">> TEST: RECV <-: {:?}", message);
    })
}
