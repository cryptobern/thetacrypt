use serde::{Deserialize, Serialize};
use network::lib::get_peers;

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    listening: bool,
    peers: Vec<Peers>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Peers {
    node_id: String,
    url: String,
}

#[tokio::main]
async fn main() {
    let test_addr = "http://127.0.0.1:26660";
    match get_peers(test_addr.to_string()).await {
        Ok(peers) => {
            println!("{:#?}", peers);
            // for peer in peers {
            //     println!("node id: {:#?}", peer.node_id);
            //     println!("node url: {:#?}", peer.url);
            // }
        },
        Err(err) => println!("Error: {}", err),
    }
}