use libp2p::gossipsub::{IdentTopic as GossibsubTopic};
use libp2p::Multiaddr;
use network::channel::channel::{create_u8_chn, create_gossipsub_chn};
use network::setup::gossipsub::gossipsub_tokio_setup::init;
use std::time::Duration;
use tokio::time;
// use network::network_info::rpc_net_info::get_tendermint_net_info;
// use network::network_info::rpc_status::get_tendermint_status;
// use network::network_info::address_converter::{get_listen_multiaddr, get_dial_multiaddr};

#[tokio::main]
async fn main() {
    // Create a Gossipsub topic
    let topic = GossibsubTopic::new("gossipsub broadcast");

    // create channel to submit messages to the floodsub broadcast
    let (chn_send_out, chn_rec_out) = create_u8_chn();

    // create channel to submit incoming messages from the floodsub broadcast
    let (chn_send_in, mut chn_rec_in) = create_gossipsub_chn();

    // sends a Vec<u8> into the channel as spawned thread
    tokio::spawn(async move {
        // test vector
        let mut my_vec: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
        // repeated sending in endless loop for testing purpose
        for count in 0.. {
            // waits for sending the next message
            time::sleep(Duration::from_millis(5000)).await;
            my_vec[0] = count; // to keep track of the messages
            my_vec[1] = rand::random(); // to prevent dublicate messages
            // sends Vec<u8> into the channel
            chn_send_out.send(my_vec.to_vec()).unwrap();
        }
    });
    

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

    
    // temp solution (using cli arguments for listener and dialing addresses):
    // first cli argument: listen_port
    if let Some(listen_on) = std::env::args().nth(1) {
        let listen_addr = format!("{}{}", "/ip4/0.0.0.0/tcp/", listen_on); // default address

        // second cli argument: peer address (port) to dial
        if let Some(dial_to) = std::env::args().nth(2) {
            let dial = format!("{}{}", "/ip4/127.0.0.1/tcp/", dial_to); // default address
            let dial_addr: Multiaddr = dial.parse().expect("User to provide valid address.");

            // kick off gossipsub broadcast for given topic, listening and dialing addresses and channels
            tokio::spawn(async move {
                init(topic,
                    listen_addr.parse().unwrap(),
                    dial_addr,
                    chn_rec_out,
                    chn_send_in).await;
            });
        } else {
            println!("info: provide a port to connect to.");
        }
    } else {
        println!("provide a port as listener address.");
    }

    // receive incoming messages via the internal channel
    while let Some(message) = chn_rec_in.recv().await {
        print!("RECV <-: {:?}", message.data); // vec<u8>
        println!(" FROM: {:?}", message.source.unwrap());
    }
}