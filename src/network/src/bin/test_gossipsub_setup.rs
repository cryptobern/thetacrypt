use libp2p::gossipsub::IdentTopic as GossibsubTopic;
use libp2p::Multiaddr;
// use network::setup::gossipsub_setup::init;
use network::setup::gossipsub_tokio_setup::init;
use network::send::send::create_channel;
use std::time::Duration;
use tokio::time;

#[tokio::main]
async fn main() {
    // Create a Gossipsub topic
    let topic = GossibsubTopic::new("gossipsub broadcast");

    // create channel to send messages to the floodsub broadcast
    let (channel_sender, channel_receiver) = create_channel();

    // sends a Vec<u8> into the channel as spawned thread
    tokio::spawn(async move {
        // test vector
        let mut my_vec: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
        // repeated sending in endless loop for testing purpose
        for count in 0.. {
            my_vec[0] = count; // to keep track of the messages
            my_vec[1] = rand::random(); // to prevent dublicate messages
            // sends Vec<u8> into the channel
            channel_sender.send(my_vec.to_vec()).unwrap();
            // waits for sending the next message
            time::sleep(Duration::from_millis(1000)).await;
        }
    });
    
    // TODO: get listener address and dialing address from tendermint RPC endpoint
    let base_listen_addr = "/ip4/0.0.0.0/tcp/";
    let base_dial_addr = "/ip4/127.0.0.1/tcp/";
    
    // temp solution:
    // first cli argument: listen_addresse
    if let Some(listen_on) = std::env::args().nth(1) {
        let listen_address = format!("{}{}", base_listen_addr, listen_on);

        // second cli argument: peer address to dial
        if let Some(dial_to) = std::env::args().nth(2) {
            let dial = format!("{}{}", base_dial_addr, dial_to);
            let dial_address: Multiaddr = dial.parse().expect("User to provide valid address.");
            // kick off gossipsub broadcast for given topic, listening and dialing address and channel
            init(topic, listen_address.parse().unwrap(), dial_address, channel_receiver).await;
        } else {
            println!("info: no port number to connect with provided.");
        }
    } else {
        println!("provide a port number as listener address.");
    }
}