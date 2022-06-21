use libp2p::floodsub;
use floodsub::Topic;
use once_cell::sync::Lazy;
use tokio::sync::mpsc;
use network::send::send::message_sender;
use network::setup::setup::init_setup;

#[tokio::main]
async fn main() {
    
    let topic: Lazy<Topic> = Lazy::new(|| Topic::new("floodsub broadcast"));
    let listen_addr = "/ip4/0.0.0.0/tcp/0";

    // create channel
    let (tx, rx) = mpsc::unbounded_channel();
    // sends a Vec<u8> into the spawned channel
    let my_vec: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
    tokio::spawn(message_sender(my_vec, tx));

    // setup swarm and event loop
    init_setup(topic, listen_addr.to_string(), rx).await;

}