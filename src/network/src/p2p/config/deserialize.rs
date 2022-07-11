use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub servers: Server,
}

#[derive(Deserialize)]
pub struct Server {
    pub ids: Vec<u32>,
    pub ips: Vec<String>,
    pub p2p_ports: Vec<u32>,
    pub rpc_ports: Vec<u32>,
    pub listen_address: String,
}