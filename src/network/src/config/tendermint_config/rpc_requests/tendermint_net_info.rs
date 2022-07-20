use std::error::Error;
use reqwest;
use crate::config::tendermint_config::deserialize::{RPCResult, NetInfoResult};

// send request to RPC endpoint of tendermint node
pub async fn get_tendermint_net_info(address: String) -> Result<RPCResult<NetInfoResult>, Box<dyn Error>> {
    let req_url = address + "/net_info";
    let response = reqwest::get(req_url).await?.json::<RPCResult<NetInfoResult>>().await?;
    Ok(response)
}