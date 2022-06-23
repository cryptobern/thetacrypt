use floodsub::Topic;
use libp2p::floodsub;
use network::send::send::create_channel;
use network::setup::floodsub_setup::init;
use once_cell::sync::Lazy;
use std::time::Duration;
use tokio::time;

#[tokio::main]
async fn main() {
    
    let topic: Lazy<Topic> = Lazy::new(|| Topic::new("floodsub broadcast"));

    // create channel to send messages to the floodsub broadcast
    let (channel_sender, channel_receiver) = create_channel();

    // test vector
    let mut my_vec: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();

    // sends a Vec<u8> into the channel as spawned thread
    tokio::spawn(async move {
        // repeated sending in endless loop for testing purpose
        for count in 0.. {
            my_vec[0] = count;
            // sends Vec<u8> into the channel
            channel_sender.send(my_vec.to_vec()).unwrap();
            // waits for sending the next message
            time::sleep(Duration::from_millis(500)).await;
        }
    });

    // setup swarm, listener and event loop
    init(topic, channel_receiver).await;

}