use libp2p::core::transport::Boxed;
use tendermint_rpc::{HttpClient, Client};
use tendermint_rpc::Response;
use serde::ser::Error;

// NOT WORKING YET WITH TENDERMINT_RPC!
pub async fn get_local_peer_id() {
// pub async fn get_local_peer_id() -> Result<Boxed<dyn Response>, Box<dyn Error>> {
    let client = HttpClient::new("http://127.0.0.1:26657")
        .unwrap();

    match client.status().await {
        Ok(res) => {
            println!("res: {:?}", res);
            println!("node id: {:?}", res.node_info.id);
            res.node_info.id;
        },
        Err(err) => println!("error: {}", err),
    }
}