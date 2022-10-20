use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub p2p_base_listen_address: String,
    pub rpc_base_listen_address: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RPCResult<R> {
    jsonrpc: String,
    id: i8,
    pub result: R,
}

// get node ids from tendermint nodes in the network
#[derive(Serialize, Deserialize, Debug)]
pub struct NetInfoResult {
    pub listening: bool,
    pub n_peers: String,
    pub peers: Vec<Peer>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Peer {
    pub node_id: String,
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatusResult {
    pub node_info: NodeInfo,
    pub sync_info: SyncInfo,
    pub validator_info: ValidatorInfo,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeInfo {
    pub id: String,
    pub listen_addr: String,
    pub other: Other,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Other {
    pub tx_index: String,
    pub rpc_address: String,
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