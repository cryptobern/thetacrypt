use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub ids: Vec<u32>,
    pub ips: Vec<String>,
    pub p2p_ports: Vec<u16>,
    pub rpc_ports: Vec<u16>,
    pub base_listen_address: String,
}
