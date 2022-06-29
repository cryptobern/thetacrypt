use chrono::format;
use libp2p::gossipsub::IdentTopic as GossibsubTopic;
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use network::lib::type_of;
// use network::setup::gossipsub_setup::init;
use network::setup::gossipsub_tokio_setup::init;
use network::send::send::create_channel;
use std::time::Duration;
use tokio::time;
use crate::network_info::rpc_net_info::get_tendermint_net_info;
use crate::network_info::rpc_status::get_tendermint_status;
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
    
    let rpc_address = "http://127.0.0.1:26657";
    let multi_addr_prefix = "/ip4/";

    // get local listener address from local tendermint RPC endpoint
    let mut multi_addr_listen: Multiaddr = format!("{}{}", "/ip4/0.0.0.0/tcp/", "26657").parse().unwrap();
    match get_tendermint_status(rpc_address.to_string()).await {
        Ok(response) => {
            let mut local_node_listen_address = response.result.node_info.listen_addr;
            let mut iter = local_node_listen_address.chars();
            iter.by_ref().nth(5); // remove leading 48 characters to retrieve only the ip
            local_node_listen_address = iter.as_str().to_string();
            let v: Vec<&str> = local_node_listen_address.split(':').collect(); // separate ip and port
            let listen_ip = v[0];
            let listen_port = v[1];
            // construct valid MultiAddr
            multi_addr_listen = format!("{}{}", multi_addr_prefix, listen_ip).parse().unwrap();
            multi_addr_listen.push(Protocol::Tcp(listen_port.parse::<u16>().unwrap()));
        },
        Err(err) => println!("Error: {}", err),
    }

    // get peer addresses from local tendermint RPC endpoint
    let mut multi_addr_dial: Multiaddr = format!("{}{}", "/ip4/127.0.0.1/tcp/", "26657").parse().unwrap();
    let mut peer_urls: Vec<String> = Vec::new();
    match get_tendermint_net_info(rpc_address.to_string()).await {
        Ok(response) => {
            for peer in response.result.peers {
                peer_urls.push(peer.url);
            }
            let temp_dial_addr = &peer_urls[0]; // take first (or another) peer url in mconn-format (nodeId@)ip)
            let mut iter = temp_dial_addr.chars();
            iter.by_ref().nth(48); // remove leading 48 characters to retrieve only the ip
            let addr_iter = &iter.as_str().to_string();
            let w: Vec<&str> = addr_iter.split(':').collect(); // separate ip and port
            let dial_ip = w[0];
            let dial_port = w[1];
            // construct valid MultiAddr
            multi_addr_dial = format!("{}{}", multi_addr_prefix, dial_ip).parse().unwrap();
            multi_addr_dial.push(Protocol::Tcp(dial_port.parse::<u16>().unwrap()));
        },
        Err(err) => println!("Error: {}", err),
    }

    init(topic, multi_addr_listen, multi_addr_dial, channel_receiver).await;
    
    // temp solution:
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