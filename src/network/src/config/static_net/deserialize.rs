use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub ids: Vec<u32>,
    pub ips: Vec<String>,
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub base_listen_address: String,
}