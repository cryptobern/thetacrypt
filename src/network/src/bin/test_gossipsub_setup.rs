use std::{env};
use libp2p::gossipsub::{IdentTopic as GossibsubTopic};
use libp2p::Multiaddr;
use network::p2p::gossipsub::setup::init;
use network::types::message::P2pMessage;
use std::time::Duration;
use tokio::time;
use libp2p::gossipsub::GossipsubMessage;
use tokio::sync::mpsc::{self, UnboundedSender, UnboundedReceiver};
use std::str::FromStr;
// use network::network_info::rpc_net_info::get_tendermint_net_info;
// use network::network_info::rpc_status::get_tendermint_status;
// use network::network_info::address_converter::{get_listen_multiaddr, get_dial_multiaddr};

const RPC_DEFAULT_LISTEN_PORT: u32 = 50050;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    // let key_chain: KeyChain = KeyChain::from_file(&my_keyfile); 

    // Create channel for sending P2P messages received at the network module to the protocols
    let (net_to_protocols_sender, mut net_to_protocols_receiver) = tokio::sync::mpsc::channel::<P2pMessage>(32);
    let net_to_protocols_sender2 = net_to_protocols_sender.clone(); //test

    // Create channel for sending P2P messages from a protocol to the network module
    let (protocols_to_net_sender, mut protocols_to_net_receiver) = tokio::sync::mpsc::channel::<P2pMessage>(32);

    // Start the network
    println!(">> MAIN: Initiating lib_P2P-based network instance.");
    tokio::spawn(async move {
        network::p2p::gossipsub::setup::init(protocols_to_net_receiver,                                           net_to_protocols_sender,
                                            my_id,)
                                            .await;
    });
    // // create channel to submit messages to the floodsub broadcast
    // let (chn_out_send, chn_out_recv) = create_u8_chn();

    // // create channel to submit incoming messages from the floodsub broadcast
    // let (chn_in_send, mut chn_in_recv) = create_gossipsub_chn();

    // // sends a Vec<u8> into the channel as spawned thread
    // tokio::spawn(async move {
    //     // test vector
    //     let mut my_vec: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
    //     // repeated sending in endless loop for testing purpose
    //     for count in 0.. {
    //         // waits for sending the next message
    //         time::sleep(Duration::from_millis(5000)).await;
    //         my_vec[0] = count; // to keep track of the messages
    //         my_vec[1] = rand::random(); // to prevent dublicate messages
    //         // sends Vec<u8> into the channel
    //         chn_out_send.send(my_vec.to_vec()).unwrap();
    //     }
    // });
    

    // // get node addresses with tendermint RPC request
    // let rpc_endpoint = "http://127.0.0.1:26657";
    // // get local listener address from local tendermint RPC endpoint
    // let mut listen_addr: Multiaddr = format!("{}{}", "/ip4/0.0.0.0/tcp/", "26657").parse().unwrap(); // default address
    // match get_tendermint_status(rpc_endpoint.to_string()).await {
    //     Ok(res) => {
    //         listen_addr = get_listen_multiaddr(res);
    //     },
    //     Err(err) => println!("Error: {}", err),
    // }

    // // get peer addresses from local tendermint RPC endpoint
    // let mut dial_addr: Multiaddr = format!("{}{}", "/ip4/127.0.0.1/tcp/", "26657").parse().unwrap(); // default address
    // match get_tendermint_net_info(rpc_endpoint.to_string()).await {
    //     Ok(res) => {
    //         dial_addr = get_dial_multiaddr(res);
    //     },
    //     Err(err) => println!("Error: {}", err),
    // }

    // init(topic, listen_addr, dial_addr, channel_receiver).await;


    // kick off gossipsub broadcast for given topic, listening and dialing addresses and channels
    // tokio::spawn(async move {
    //     init(chn_out_recv,chn_in_send).await;
    // });
    
    // receive incoming messages via the internal channel
    Ok(while let Some(message) = net_to_protocols_receiver.recv().await {
        print!("RECV <-: {:?}", message); // vec<u8>
        // println!(" FROM: {:?}", message.source.unwrap());
    })
}

// creates a channel to send messages for broadcasting to the swarm.
// returns the sender to add messages to the internal channel
// and the receiver that retrieves messages from the channel to broadcast them to the network.
pub fn create_u8_chn() -> (UnboundedSender<Vec<u8>>, UnboundedReceiver<Vec<u8>>) {
    mpsc::unbounded_channel()
}

pub fn create_gossipsub_chn() -> (UnboundedSender<GossipsubMessage>, UnboundedReceiver<GossipsubMessage>) {
    mpsc::unbounded_channel()
}