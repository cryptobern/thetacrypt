use libp2p::multiaddr::Multiaddr;
use std::str::FromStr;
use log::info;
use serde::{Deserialize, Serialize};
use utils::server::types::{Peer, ProxyNode, ServerConfig};

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct NetworkPeer{
    pub id: u32, 
    pub ip: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkProxy{
    pub ip: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkConfig {
    pub local_peer: NetworkPeer,
    pub peers: Option<Vec<NetworkPeer>>,
    pub proxy: Option<NetworkProxy>,
    pub base_listen_address: String,
}

impl NetworkPeer{
    pub fn new(peer: &Peer)-> Self{
        return NetworkPeer{
            id: peer.id,
            ip: peer.ip.clone(),
            port: peer.p2p_port
        }
    }
}

impl NetworkProxy{
    pub fn new(peer: &ProxyNode)-> Self{
        return NetworkProxy{
            ip: peer.ip.clone(),
            port: peer.port
        }
    }
}

impl NetworkConfig {

    pub fn new(server_config: &ServerConfig)-> Result<Self, String>{

        let mut local_peer = NetworkPeer::default();

        if let Some(peer) = server_config.self_peer(){
            local_peer = NetworkPeer::new(peer);
        }

        if local_peer == NetworkPeer::default() {
            return Err("No local information to setup the peer".to_string())
        } 

        let mut network_peers:Option<Vec<NetworkPeer>> = None;
        
        let server_peers:Vec<NetworkPeer> = server_config.peers
            .iter()
            .map(|peer|
                NetworkPeer::new(peer)
            )
            .collect();

        if server_peers.len() > 1 {
            network_peers = Some(server_peers);
        }

        let mut proxy_peer:Option<NetworkProxy> = None;

        if let Some(proxy) = server_config.get_proxy_node(){
            proxy_peer = Some(NetworkProxy::new(proxy));
        }
        
        Ok(NetworkConfig{
            local_peer,
            peers: network_peers,
            proxy: proxy_peer,
            base_listen_address: server_config.listen_address.clone(),
        })
    }

    pub fn get_p2p_listen_addr(&self) -> Multiaddr {
        info!("{}, {}", self.base_listen_address, self.local_peer.port);
        format!("/ip4/{}/tcp/{}", self.base_listen_address, self.local_peer.port)
        .parse()
        .expect(&format!(
            ">> NET: Fatal error: Could not open P2P listen port {}.",
            self.local_peer.port
        ))
    }
}