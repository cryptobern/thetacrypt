use std::error::Error;
use reqwest;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
    pub struct PeerResponse {
        pub node_info: NodeInfo,
        pub sync_info: SyncInfo,
        pub validator_info: ValidatorInfo,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct NodeInfo {
        pub id: String,
        pub listen_addr: String,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct SyncInfo {
        pub latest_block_hash: String,  
        pub latest_block_height: String,
        pub latest_block_time: String,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct ValidatorInfo {
        pub address: String,
        pub pub_key: PubKey,
        pub voting_power: String,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct PubKey {
        pub r#type: String, // escape `type` with r# to use it as an identifier
        pub value: String,
    }

    // send request to RPC endpoint of tendermint node
    pub async fn get_peer_info(address: String) -> Result<PeerResponse, Box<dyn Error>> {
        let req_url = address + "/status";
        let response = reqwest::get(req_url).await?.json::<PeerResponse>().await?;
        Ok(response)
    }