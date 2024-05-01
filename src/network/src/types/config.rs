use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkPeer{
    pub id: u32, 
    pub ip: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkProxy{
    pub ip: u32,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkConfig {
    pub local_peer: NetworkPeer,
    pub peers: Option<Vec<NetworkPeer>>,
    pub proxy: Option<NetworkProxy>,
    pub base_listen_address: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub p2p_port: u16,
    pub proxy_addr: String,
    pub proxy_port: u16,
}


impl NetworkConfig {

    pub fn get_p2p_listen_addr(&self) -> Multiaddr {
        format!("{}{}", self.base_listen_address, self.local_peer.port)
        .parse()
        .expect(&format!(
            ">> NET: Fatal error: Could not open P2P listen port {}.",
            self.local_peer.port
        ))
    }
}