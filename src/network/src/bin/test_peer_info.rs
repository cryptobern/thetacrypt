// use network::lib::{get_peers, get_peer_info};
use crate::network_info::peers::get_peers;
use crate::network_info::local_node::get_peer_info;
mod network_info;

#[tokio::main]
async fn main() {
    let test_addr = "http://127.0.0.1:26657";

    match get_peers(test_addr.to_string()).await {
        Ok(response) => {
            println!("{:#?}", response);
            // println!("no. of other peers {:#?}", response.n_peers);
            // for peer in response.peers {
            //     println!("node id: {:#?}", peer.node_id);
            //     println!("node url: {:#?}", peer.url);
            // }
        },
        Err(err) => println!("Error: {}", err),
    }

    match get_peer_info(test_addr.to_string()).await {
        Ok(response) => {
            println!("{:#?}", response);
        },
        Err(err) => println!("Error: {}", err),
    }
}