use std::{convert::TryFrom, fs, net::IpAddr, path::PathBuf, process::exit, str::FromStr};

use clap::Parser;
use rand::seq::SliceRandom;
use utils::confgen::cli::{ConfgenCli, PortStrategy};

use log::{error, info};
use utils::client::types::{ClientConfig, PeerPublicInfo};
use utils::server::{
    dirutil,
    types::{Peer, ProxyNode, ServerConfig, ServerProxyConfig},
};

fn main() {
    env_logger::init();

    let confgen_cli = ConfgenCli::parse();
    let ips = match ips_from_file(&confgen_cli.ip_file) {
        Ok(ips) => ips,
        Err(e) => {
            error!("{}", e);
            exit(1);
        }
    };

    let mut ips_proxy_nodes = Vec::new();

    if let Some(path) = confgen_cli.integration_file {
        ips_proxy_nodes = match ips_from_file(&path) {
            Ok(ips) => ips,
            Err(e) => {
                error!("{}", e);
                exit(1);
            }
        };
    }

    match dirutil::ensure_sane_output_directory(&confgen_cli.outdir, false) {
        Ok(_) => info!("Using output directory: {}", &confgen_cli.outdir.display()),
        Err(e) => {
            error!("Invalid output directory: {}, aborting...", e,);
            exit(1);
        }
    }

    if confgen_cli.integration {
        match run_integration(
            ips,
            ips_proxy_nodes,
            confgen_cli.rpc_port,
            confgen_cli.p2p_port,
            confgen_cli.port_strategy,
            confgen_cli.listen_address,
            confgen_cli.outdir,
        ) {
            Ok(_) => {
                info!("Config generation successful, all config files saved to disk");
            }
            Err(e) => {
                error!("Config generation failed: {}", e);
                exit(1);
            }
        }
    } else {
        match run(
            ips,
            confgen_cli.rpc_port,
            confgen_cli.p2p_port,
            confgen_cli.port_strategy,
            confgen_cli.shuffle_peers,
            confgen_cli.listen_address,
            confgen_cli.outdir,
            confgen_cli.event_file,
        ) {
            Ok(_) => {
                info!("Config generation successful, all config files saved to disk");
            }
            Err(e) => {
                error!("Config generation failed: {}", e);
                exit(1);
            }
        }
    }
}

fn ips_from_file(path: &PathBuf) -> Result<Vec<String>, String> {
    let input = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => return Err(format!("Error reading IPs: {}", e)),
    };
    let lines = input.lines();

    let mut ips = Vec::new();
    for line in lines {
        match IpAddr::from_str(line) {
            Ok(_) => {
                ips.push(line.to_string());
            }
            Err(e) => {
                return Err(format!(
                    "Error reading IPs from file. {} was not a valid IP: {}",
                    line, e
                ))
            }
        }
    }

    Ok(ips)
}

fn run(
    ips: Vec<String>,
    rpc_port: u16,
    p2p_port: u16,
    port_strategy: PortStrategy,
    shuffle_peers: bool,
    listen_address: String,
    outdir: PathBuf,
    event_file: Option<PathBuf>,
) -> Result<(), String> {
    info!("Generating configuration structs");
    let peers: Vec<Peer> = ips
        .iter()
        .enumerate()
        .map(|(i, ip)| {
            let (rpc_port, p2p_port) = match port_strategy {
                PortStrategy::Consecutive => (
                    // More than 2^16 peers? What are we, an ISP?
                    rpc_port + u16::try_from(i).unwrap(),
                    p2p_port + u16::try_from(i).unwrap(),
                ),
                PortStrategy::Static => (rpc_port, p2p_port),
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

    let configs: Vec<ServerConfig> = ips
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let mut my_peers = peers.clone();
            if shuffle_peers {
                let mut rng = rand::thread_rng();
                my_peers.shuffle(&mut rng);
            }

            ServerConfig::new(
                u32::try_from(i).unwrap(),
                listen_address.clone(),
                my_peers,
                event_file.clone(),
            )
            .unwrap()
        })
        .collect();

    let public_peers: Vec<PeerPublicInfo> = peers
        .iter()
        .enumerate()
        .map(|(_, peer_ref)| {
            let peer = peer_ref.clone();
            PeerPublicInfo {
                id: peer.id,
                ip: peer.ip,
                rpc_port: peer.rpc_port,
            }
        })
        .collect();

    let client_config = ClientConfig::new(public_peers).unwrap();

    info!("Writing configurations to disk");
    for cfg in configs {
        let mut outfile = outdir.clone();
        outfile.push(format!("server_{:?}.json", cfg.id));

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

    info!("Writing client configuration to disk");
    let mut outfile = outdir.clone();
    outfile.push("client.json");

    let data = match serde_json::to_string(&client_config) {
        Ok(s) => s,
        Err(e) => return Err(format!("JSON serialization failed: {}", e)),
    };

    match fs::write(outfile, data) {
        Ok(_) => {}
        Err(e) => {
            return Err(format!("Failed to write to file: {}", e));
        }
    }

    Ok(())
}

fn run_integration(
    ips: Vec<String>,
    ips_proxy_nodes: Vec<String>,
    rpc_port: u16,
    p2p_port: u16,
    port_strategy: PortStrategy,
    listen_address: String,
    outdir: PathBuf,
) -> Result<(), String> {
    info!("Generating configuration structs");
    let _peers: Vec<Peer> = ips
        .iter()
        .enumerate()
        .map(|(i, ip)| {
            let (rpc_port, p2p_port) = match port_strategy {
                PortStrategy::Consecutive => (
                    // More than 2^16 peers? What are we, an ISP?
                    rpc_port + u16::try_from(i).unwrap(),
                    p2p_port + u16::try_from(i).unwrap(),
                ),
                PortStrategy::Static => (rpc_port, p2p_port),
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

    // TODO:
    // check that the two vectors of ips are of equal lenght
    // check if we need the local ip

    let configs: Vec<ServerProxyConfig> = ips_proxy_nodes
        .iter()
        .enumerate()
        .map(|(i, ip)| {
            let (rpc_port, p2p_port) = match port_strategy {
                PortStrategy::Consecutive => (
                    // More than 2^16 peers? What are we, an ISP?
                    rpc_port + u16::try_from(i).unwrap(),
                    p2p_port + u16::try_from(i).unwrap(),
                ),
                PortStrategy::Static => (rpc_port, p2p_port),
            };
            ServerProxyConfig::new(
                u32::try_from(i).unwrap(),
                listen_address.clone(),
                p2p_port,
                rpc_port,
                ProxyNode { ip: ip.to_string() },
            )
            .unwrap()
        })
        .collect();

    info!("Writing configurations to disk");
    for cfg in configs {
        let mut outfile = outdir.clone();
        outfile.push(format!("server_{:?}.json", cfg.id));

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
