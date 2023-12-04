use serde::{Deserialize, Serialize};
use std::fs;

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

/// PublicInfo to reach the server and its RPC endpoint.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerPublicInfo {
    pub id: u32,
    pub ip: String,
    pub rpc_port: u16,
}

/// Configuration of the server binary.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientConfig {
    pub peers: Vec<PeerPublicInfo>,
}

impl ClientConfig {
    /// Read a server's configuration from a JSON encoding on disk.
    pub fn from_file(file: &PathBuf) -> Result<ClientConfig, String> {
        let data = match fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => return Err(format!("Error reading config file: {}", e)),
        };

        match ClientConfig::from_json(&data) {
            Ok(cfg) => return Ok(cfg),
            Err(e) => return Err(format!("Error parsing config file: {}", e)),
        }
    }

    /// Build a server's configuration based on a JSON serialization.
    pub fn from_json(data: &str) -> Result<ClientConfig, String> {
        let cfg: ClientConfig = match serde_json::from_str(data) {
            Ok(cfg) => cfg,
            Err(e) => return Err(format!("Invalid JSON: {}", e)),
        };

        ClientConfig::new(cfg.peers)
    }

    /// Initialize a new config struct. Performs a sanity check of passed values.
    pub fn new(peers: Vec<PeerPublicInfo>) -> Result<ClientConfig, String> {
        for peer in &peers {
            match IpAddr::from_str(&peer.ip) {
                Ok(_) => {}
                Err(e) => return Err(format!("Invalid IP for peer {}: {}", peer.id, e)),
            }
        }

        Ok(ClientConfig { peers })
    }

    /// Get list of all peers' IDs, sorted by the order in which they appear in the config file.
    pub fn peer_ids(&self) -> Vec<u32> {
        self.peers.iter().map(|p| p.id).collect()
    }

    /// Get list of all peers' IPs, sorted by the order in which they appear in the config file.
    pub fn peer_ips(&self) -> Vec<String> {
        self.peers.iter().map(|p| p.ip.clone()).collect()
    }

    /// Get list of all peers' RPC ports, sorted by the order in which they appear in the config
    /// file.
    pub fn peer_rpc_ports(&self) -> Vec<u16> {
        self.peers.iter().map(|p| p.rpc_port).collect()
    }
}
