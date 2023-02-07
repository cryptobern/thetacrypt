use std::{convert::TryFrom, fs, path::PathBuf};

use log::info;
use rand::seq::SliceRandom;

use crate::server::config::{self, Config, Peer};

use self::cli::PortMappingStrategy;

pub mod cli;

pub fn run(
    ips: Vec<String>,
    rpc_port: u16,
    p2p_port: u16,
    port_mapping_strategy: PortMappingStrategy,
    shuffle_peers: bool,
    listen_address: String,
    outdir: PathBuf,
) -> Result<(), String> {
    info!("Generating configuration structs");
    let peers: Vec<Peer> = ips
        .iter()
        .enumerate()
        .map(|(i, ip)| {
            let (rpc_port, p2p_port) = match port_mapping_strategy {
                PortMappingStrategy::Consecutive => (
                    // More than 2^16 peers? What are we, an ISP?
                    rpc_port + u16::try_from(i).unwrap(),
                    p2p_port + u16::try_from(i).unwrap(),
                ),
                PortMappingStrategy::Static => (rpc_port, p2p_port),
            };

            Peer {
                // This will fail if we ever have more than 2^32 peers, but that is unlikely. :)
                id: u32::try_from(i).unwrap(),
                ip: String::from(ip),
                rpc_port,
                p2p_port,
            }
        })
        .collect();

    let configs: Vec<Config> = ips
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let mut my_peers = peers.clone();
            if shuffle_peers {
                let mut rng = rand::thread_rng();
                my_peers.shuffle(&mut rng);
            }

            config::new(u32::try_from(i).unwrap(), listen_address.clone(), my_peers).unwrap()
        })
        .collect();

    info!("Writing configurations to disk");
    for cfg in configs {
        let mut outfile = outdir.clone();
        outfile.push(format!("node_{:03}.json", cfg.id));

        let data = match serde_json::to_string(&cfg) {
            Ok(s) => s,
            Err(e) => return Err(format!("JSON serialization failed: {}", e)),
        };

        match fs::write(outfile, data) {
            Ok(_) => {}
            Err(e) => {
                return Err(format!("Failed to write to file: {}", e));
            }
        }
    }

    Ok(())
}
