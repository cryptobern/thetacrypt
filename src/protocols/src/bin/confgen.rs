use std::{path::PathBuf, convert::TryFrom, fs, net::IpAddr, process::exit, str::FromStr};

use clap::Parser;
use rand::seq::SliceRandom;

use log::{error, info};

use protocols::{server::{types::{Peer, ServerConfig}, dirutil}, confgen::cli::{ConfgenCli, PortStrategy}};



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

    match dirutil::ensure_sane_output_directory(&confgen_cli.outdir, false) {
        Ok(_) => info!("Using output directory: {}", &confgen_cli.outdir.display()),
        Err(e) => {
            error!("Invalid output directory: {}, aborting...", e,);
            exit(1);
        }
    }

    match run(
        ips,
        confgen_cli.rpc_port,
        confgen_cli.p2p_port,
        confgen_cli.port_strategy,
        confgen_cli.shuffle_peers,
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

            ServerConfig::new(u32::try_from(i).unwrap(), listen_address.clone(), my_peers).unwrap()
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
