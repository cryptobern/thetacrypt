use std::error::Error;
use reqwest;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    listening: bool,
    // listeners: Vec<Listener>,
    peers: Vec<Peers>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Peers {
    node_id: String,
    url: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let http_response = reqwest::get("http://127.0.0.1:26657/net_info").await?;
    let response = http_response.json::<Response>().await?;
    println!("{:#?}", response.peers);

    Ok(())
}