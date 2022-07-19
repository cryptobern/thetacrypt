use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub servers: Server,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Server {
    pub ids: Vec<u32>,
    pub ips: Vec<String>,
    pub p2p_ports: Vec<u16>,
    pub rpc_ports: Vec<u16>,
    pub listen_address: String,
}