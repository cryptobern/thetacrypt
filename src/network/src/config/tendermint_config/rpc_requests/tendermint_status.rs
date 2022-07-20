use std::error::Error;
use reqwest;
use crate::config::tendermint_config::deserialize::{RPCResult, StatusResult};

// send request to RPC endpoint of tendermint node
pub async fn get_tendermint_status(address: String) -> Result<RPCResult<StatusResult>, Box<dyn Error>> {
    let req_url = address + "/status";
    let response = reqwest::get(req_url).await?.json::<RPCResult<StatusResult>>().await?;
    Ok(response)
}