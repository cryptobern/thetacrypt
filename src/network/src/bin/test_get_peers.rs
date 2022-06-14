use network::lib::get_peers;

#[tokio::main]
async fn main() {
    let test_addr = "http://127.0.0.1:26660";
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
}