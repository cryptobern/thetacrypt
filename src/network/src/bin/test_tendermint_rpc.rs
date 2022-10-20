use tendermint_rpc::{HttpClient, Client};

#[tokio::main]
async fn main() {
    let client = HttpClient::new("http://127.0.0.1:26657")
        .unwrap();

    match client.status().await { // works
    // match client.net_info().await { // serde parse error, missing field `node_info` at line 1 column 269
        Ok(res) => {
            println!("res: {:?}", res);
            // println!("node id: {:?}", res.node_info.id); // from status request
        },
        Err(err) => println!("error: {}", err),
    }
}