use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A single peer of this server.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Peer {
    pub id: u32,
    pub ip: String,
    pub p2p_port: u16,
}

/// A proxy node for remote delegation of networking task
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProxyNode {
    pub ip: String,
    pub port: u16,
}

/// Configuration of the server binary.
#[derive(Serialize, Deserialize, Debug)]
pub struct ServerConfig {
    /// ID of this server.
    pub id: u32,
    /// Address which the server will attempt to bind to.
    pub listen_address: String,
    /// Port used by the server to expose the RPC endpoint to an application 
    pub rpc_port: u16,
    /// Vector of peers this server will connect to. Must also contain itself as a peer. It will always exist at least one element
    pub peers: Vec<Peer>,
    /// Optional proxy node (remote) for communication delegation
    pub proxy_node: Option<ProxyNode>,
    /// Path to file in which to store benchmarking events.
    /// If not set, benchmarking events will be discarded.
    pub event_file: Option<PathBuf>,
}

impl ServerConfig {
    /// Read a server's configuration from a JSON encoding on disk.
    pub fn from_file(file: &PathBuf) -> Result<ServerConfig, String> {
        let data = match fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => return Err(format!("Error reading config file: {}", e)),
        };

        match ServerConfig::from_json(&data) {
            Ok(cfg) => return Ok(cfg),
            Err(e) => return Err(format!("Error parsing config file: {}", e)),
        }
    }

    /// Build a server's configuration based on a JSON serialization.
    pub fn from_json(data: &str) -> Result<ServerConfig, String> {
        let cfg: ServerConfig = match serde_json::from_str(data) {
            Ok(cfg) => cfg,
            Err(e) => return Err(format!("Invalid JSON: {}", e)),
        };

        ServerConfig::new(cfg.id, cfg.listen_address, cfg.rpc_port, cfg.peers, cfg.proxy_node, cfg.event_file)
    }

    /// Initialize a new config struct. Performs a sanity check of passed values.
    pub fn new(
        id: u32,
        listen_address: String,
        rpc_port: u16,
        peers: Vec<Peer>,
        proxy_node: Option<ProxyNode>,
        event_file: Option<PathBuf>,
    ) -> Result<ServerConfig, String> {
        match IpAddr::from_str(&listen_address) {
            Ok(_) => {}
            Err(e) => return Err(format!("Invalid value for LISTEN_ADDRESS: {}", e)),
        }

        for peer in &peers {
            match IpAddr::from_str(&peer.ip) {
                Ok(_) => {}
                Err(e) => return Err(format!("Invalid IP for peer {}: {}", peer.id, e)),
            }
        }

        Ok(ServerConfig {
            id,
            listen_address,
            rpc_port,
            peers,
            proxy_node,
            event_file,
        })
    }

    /// Get list of all peers' IDs, sorted by the order in which they appear in the config file.
    pub fn peer_ids(&self) -> Vec<u32> {
        self.peers.iter().map(|p| p.id).collect()
    }

    /// Get list of all peers' IPs, sorted by the order in which they appear in the config file.
    pub fn peer_ips(&self) -> Vec<String> {
        self.peers.iter().map(|p| p.ip.clone()).collect()
    }

    /// Get list of all peers' P2P ports, sorted by the order in which they appear in the config
    /// file.
    pub fn peer_p2p_ports(&self) -> Vec<u16> {
        self.peers.iter().map(|p| p.p2p_port).collect()
    }

    /// Get this server's P2P port. Returns an error if this server is not found in the list of peers.
    pub fn my_p2p_port(&self) -> Result<u16, String> {
        match self.self_peer() {
            Some(peer) => Ok(peer.p2p_port),
            None => Err(format!(
                "Config for server with ID {} not found in list of configured peers",
                self.id
            )),
        }
    }

    pub fn get_proxy_node(&self) -> Option<&ProxyNode>{
        return self.proxy_node.as_ref();
    }

    /// Get peer which corresponds to this server itself.
    pub fn self_peer(&self) -> Option<&Peer> {
        for peer in &self.peers {
            if peer.id == self.id {
                return Some(peer);
            }
        }

        return None;
    }
}

// /// Configuration of the server binary.
// #[derive(Serialize, Deserialize, Debug)]
// pub struct ServerProxyConfig {
//     /// ID of this server.
//     pub id: u32,
//     /// Address which the server will attempt to bind to.
//     pub listen_address: String,
//     pub p2p_port: u16,
//     pub rpc_port: u16,
//     /// Proxy node for forwarding the messages into a blockchian platform
//     pub proxy_node: ProxyNode,
//     pub event_file: Option<PathBuf>,
// }

// impl ServerProxyConfig {
//     /// Read a server's configuration from a JSON encoding on disk.
//     pub fn from_file(file: &PathBuf) -> Result<ServerProxyConfig, String> {
//         let data = match fs::read_to_string(file) {
//             Ok(s) => s,
//             Err(e) => return Err(format!("Error reading config file: {}", e)),
//         };

//         match ServerProxyConfig::from_json(&data) {
//             Ok(cfg) => return Ok(cfg),
//             Err(e) => return Err(format!("Error parsing config file: {}", e)),
//         }
//     }

//     /// Build a server's configuration based on a JSON serialization.
//     pub fn from_json(data: &str) -> Result<ServerProxyConfig, String> {
//         let cfg: ServerProxyConfig = match serde_json::from_str(data) {
//             Ok(cfg) => cfg,
//             Err(e) => return Err(format!("Invalid JSON: {}", e)),
//         };

//         ServerProxyConfig::new(
//             cfg.id,
//             cfg.listen_address,
//             cfg.p2p_port,
//             cfg.rpc_port,
//             cfg.proxy_node,
//             cfg.event_file,
//         )
//     }

//     /// Initialize a new config struct. Performs a sanity check of passed values.
//     pub fn new(
//         id: u32,
//         listen_address: String,
//         p2p_port: u16,
//         rpc_port: u16,
//         proxy_node: ProxyNode,
//         event_file: Option<PathBuf>,
//     ) -> Result<ServerProxyConfig, String> {
//         match IpAddr::from_str(&listen_address) {
//             Ok(_) => {}
//             Err(e) => return Err(format!("Invalid value for LISTEN_ADDRESS: {}", e)),
//         }

//         match IpAddr::from_str(&proxy_node.ip) {
//             Ok(_) => {}
//             Err(e) => return Err(format!("Invalid IP for peer {}: {}", id, e)),
//         }

//         Ok(ServerProxyConfig {
//             id,
//             listen_address,
//             p2p_port,
//             rpc_port,
//             proxy_node,
//             event_file,
//         })
//     }

//     pub fn my_p2p_port(&self) -> u16 {
//         return self.p2p_port;
//     }

//     /// Get this server's RPC port. Returns an error if this server is not found in the list of peers.
//     pub fn my_rpc_port(&self) -> u16 {
//         return self.rpc_port;
//     }

//     pub fn proxy_node_ip(&self) -> String {
//         return self.proxy_node.ip.clone();
//     }

//     pub fn proxy_node_port(&self) -> u16 {
//         return self.proxy_node.port.clone();
//     }

//     pub fn get_listen_addr(&self) -> String {
//         return self.listen_address.clone();
//     }
// }


