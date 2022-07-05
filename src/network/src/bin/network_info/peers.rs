use std::error::Error;
use reqwest;
use serde::{Deserialize, Serialize};

// get node ids from tendermint nodes in the network
#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkResponse {
    pub listening: bool,
    pub n_peers: String,
    pub peers: Vec<Peer>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Peer {
    pub node_id: String,
    pub url: String,
}

// send request to RPC endpoint of tendermint node
pub async fn get_peers(address: String) -> Result<NetworkResponse, Box<dyn Error>> {
    let req_url = address + "/net_info";
    let response = reqwest::get(req_url).await?.json::<NetworkResponse>().await?;
    Ok(response)
}