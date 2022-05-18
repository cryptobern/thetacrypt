use reqwest;
use std::error::Error;
use serde::Deserialize;


#[derive(Deserialize, Debug)]
struct Peer {
    node_id: i16,
    url: String,
}

#[derive(Deserialize, Debug)]
struct Response {
    listening: bool,
    listeners: Vec<String>,
    n_peers: i32,
    peers: Vec<Peer>,
}

use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // let mut map = HashMap::new();
    // map.insert("lang", "rust");
    // map.insert("body", "json");

    let client = reqwest::Client::new();
    // let res = client.post("http://127.0.0.1:26657/net_info")
    //     .json(&map)
    //     .send()
    //     .await?;
    // println!("{:#?}", res);

    let response = client
        .post("http://127.0.0.1:26657/net_info")
        .header("ACCEPT", "application/json")
        .header("CONTENT_TYPE", "application/json")
        // .json(&map)
        .send()
        .await?
        // .unwrap();
        .text()
        .await?;
    println!("{:#?}", response);

    Ok(())
}