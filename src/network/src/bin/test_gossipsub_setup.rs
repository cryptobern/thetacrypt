use libp2p::gossipsub::IdentTopic as GossibsubTopic;
use libp2p::Multiaddr;
// use network::lib::type_of;
// use network::setup::gossipsub_setup::init;
use network::setup::gossipsub::gossipsub_tokio_setup::init;
use network::send::send::create_channel;
use std::time::Duration;
use tokio::time;
use network::network_info::rpc_net_info::get_tendermint_net_info;
use network::network_info::rpc_status::get_tendermint_status;
use network::network_info::address_converter::{get_listen_multiaddr, get_dial_multiaddr};

mod network_info;

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
    
    let rpc_endpoint = "http://127.0.0.1:26657";

    // get local listener address from local tendermint RPC endpoint
    let mut listen_addr: Multiaddr = format!("{}{}", "/ip4/0.0.0.0/tcp/", "26657").parse().unwrap(); // default address
    match get_tendermint_status(rpc_endpoint.to_string()).await {
        Ok(res) => {
            listen_addr = get_listen_multiaddr(res);
        },
        Err(err) => println!("Error: {}", err),
    }

    // get peer addresses from local tendermint RPC endpoint
    let mut dial_addr: Multiaddr = format!("{}{}", "/ip4/127.0.0.1/tcp/", "26657").parse().unwrap(); // default address
    match get_tendermint_net_info(rpc_endpoint.to_string()).await {
        Ok(res) => {
            dial_addr = get_dial_multiaddr(res);
        },
        Err(err) => println!("Error: {}", err),
    }

    init(topic, listen_addr, dial_addr, channel_receiver).await;
    
    // temp solution (using cli arguments for listener and dialing addresses):
    // first cli argument: listen_address
    // if let Some(listen_on) = std::env::args().nth(1) {
        // let mut listen_address = format!("{}{}", base_listen_addr, listen_on);
        
        // match get_tendermint_status(test_addr.to_string()).await {
        //     Ok(response) => {
        //         println!("{:#?}", response);
        //         println!("node listen address: {}", response.result.node_info.listen_addr);
        //         listen_address = response.result.node_info.listen_addr;
        //     },
        //     Err(err) => println!("Error: {}", err),
        // }

        // println!("listen_address {}", listen_address);

        // second cli argument: peer address to dial
        // if let Some(dial_to) = std::env::args().nth(2) {
        //     let dial = format!("{}{}", base_dial_addr, dial_to);
        //     let dial_address: Multiaddr = dial.parse().expect("User to provide valid address.");
        //     // kick off gossipsub broadcast for given topic, listening and dialing address and channel
        //     init(topic, listen_address.parse().unwrap(), dial_address, channel_receiver).await;
        // } else {
        //     println!("info: no port number to connect with provided.");
        // }
    // } else {
    //     println!("provide a port number as listener address.");
    // }
}