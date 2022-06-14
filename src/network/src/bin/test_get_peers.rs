use network::lib::get_peers;

#[tokio::main]
async fn main() {
    let test_addr = "http://127.0.0.1:26660";
    match get_peers(test_addr.to_string()).await {
        Ok(peers) => {
            println!("{:#?}", peers);
            for peer in peers {
                println!("node id: {:#?}", peer.node_id);
                println!("node url: {:#?}", peer.url);
            }
        },
        Err(err) => println!("Error: {}", err),
    }
}