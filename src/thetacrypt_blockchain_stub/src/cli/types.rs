use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::fs;

use serde::{Deserialize, Serialize};

/// PublicInfo to reach the server and its RPC endpoint.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerP2PInfo {
    pub id: u32,
    pub ip: String,
    pub p2p_port: u16,
}

/// Configuration of the server binary.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct P2PConfig {
    pub peers: Vec<PeerP2PInfo>,
}

impl P2PConfig {
    /// Read a server's configuration from a JSON encoding on disk.
    pub fn from_file(file: &PathBuf) -> Result<P2PConfig, String> {
        let data = match fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => return Err(format!("Error reading config file: {}", e)),
        };

        match P2PConfig::from_json(&data) {
            Ok(cfg) => return Ok(cfg),
            Err(e) => return Err(format!("Error parsing config file: {}", e)),
        }
    }

    /// Build a server's configuration based on a JSON serialization.
    pub fn from_json(data: &str) -> Result<P2PConfig, String> {
        let cfg: P2PConfig = match serde_json::from_str(data) {
            Ok(cfg) => cfg,
            Err(e) => return Err(format!("Invalid JSON: {}", e)),
        };

        P2PConfig::new(cfg.peers)
    }

    /// Initialize a new config struct. Performs a sanity check of passed values.
    pub fn new(peers: Vec<PeerP2PInfo>) -> Result<P2PConfig, String> {
        for peer in &peers {
            match IpAddr::from_str(&peer.ip) {
                Ok(_) => {}
                Err(e) => return Err(format!("Invalid IP for peer {}: {}", peer.id, e)),
            }
        }

        Ok(P2PConfig { peers })
    }
}