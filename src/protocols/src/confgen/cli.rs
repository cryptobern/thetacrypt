use std::{fmt::Display, path::PathBuf};

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
pub struct ConfgenCli {
    #[arg(long, 
        help = "Port to use for listening for RPC requests.", 
        default_value_t = 51000)]
    pub rpc_port: u16,
    #[arg(
        long,
        help = "Port to use for P2P networking layer.",
        default_value_t = 50000
    )]
    pub p2p_port: u16,
    #[arg(
        short,
        long,
        help = "Address for RPC and networking layers.",
        default_value_t = String::from("0.0.0.0")
    )]
    pub listen_address: String,
    #[arg(
        long,
        help = "Strategy to use to assign P2P and RPC ports. Static uses the same ports for all servers. Consecutive starts at the provided ports, and increments them by one per server.",
        default_value_t = PortStrategy::Static,
    )]
    pub port_strategy: PortStrategy,

    #[arg(long,
        help = "Path to file containing IPs of servers, one per line. Required.")]
    pub ip_file: PathBuf,

    #[arg(
        long,
        help = "Controls whether to shuffle list of peers in each configuration file. This can help ensure that servers do not all connect to the same primary peer.",
        default_value_t = false
    )]
    pub shuffle_peers: bool,

    #[arg(
        short,
        long,
        help = "Directory in which to place generated config files. Required. Path up to output directory must exist."
    )]
    pub outdir: PathBuf,
}

/// Enum representing how ports are assigned to servers. Static uses the same port for all servers,
/// while consecutive uses incremental ports.
#[derive(ValueEnum, Debug, Clone)]
pub enum PortStrategy {
    Consecutive,
    Static,
}

impl Display for PortStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortStrategy::Consecutive => write!(f, "consecutive"),
            PortStrategy::Static => write!(f, "static"),
        }
    }
}

