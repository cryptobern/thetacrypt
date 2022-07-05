use floodsub::Topic;
use libp2p::floodsub;
use network::p2p::floodsub::floodsub_tokio_setup::init;
use network::channel::channel::create_u8_chn;
use once_cell::sync::Lazy;
use std::time::Duration;
use tokio::time;

#[tokio::main]
async fn main() {
    
    let topic: Lazy<Topic> = Lazy::new(|| Topic::new("floodsub broadcast"));

    // create channel to send messages to the floodsub broadcast
    let (channel_sender_out, channel_receiver_out) = create_u8_chn();

    // spawn a separate thread with the channel sender
    tokio::spawn(async move {
        // test vector
        let mut my_vec: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
        // repeated sending in endless loop for testing purpose
        for count in 0.. {
            my_vec[0] = count; // to keep track of the messages
            // adds Vec<u8> to the channel
            channel_sender_out.send(my_vec.to_vec()).unwrap();
            // waits for sending the next message
            time::sleep(Duration::from_millis(1000)).await;
        }
    });

    // kick off floodsub broadcast for given topic and channel
    init(topic, channel_receiver_out).await;
}