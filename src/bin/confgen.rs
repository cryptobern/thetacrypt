use std::ops::Add;
use std::{convert::TryFrom, fs, net::IpAddr, path::PathBuf, process::exit, str::FromStr};

use clap::{Parser, Error};
use rand::seq::SliceRandom;
use utils::confgen::cli::{ConfgenCli, PortStrategy};

use log::{error, info};
use utils::client::types::{ClientConfig, PeerPublicInfo};
use utils::server::{
    dirutil,
    types::{Peer, ProxyNode, ServerConfig},
};
use thetacrypt_blockchain_stub::cli::types::{P2PConfig, PeerP2PInfo};

use serde::{Deserialize, Serialize};

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

    let mut ips_proxy_nodes = None;
    let mut proxy_port: Option<u16> = None;

    if let Some(path) = confgen_cli.integration_file {
        ips_proxy_nodes = match ips_from_file(&path) {
            Ok(ips) => Some(ips),
            Err(e) => {
                error!("{}", e);
                exit(1);
            }
        };
    }

    if let Some(port) = confgen_cli.proxy_port {
        proxy_port = Some(port);
    }

    match dirutil::ensure_sane_output_directory(&confgen_cli.outdir, false) {
        Ok(_) => info!("Using output directory: {}", &confgen_cli.outdir.display()),
        Err(e) => {
            error!("Invalid output directory: {}, aborting...", e,);
            exit(1);
        }
    }

    
    match generate_configs(
        ips,
        ips_proxy_nodes,
        confgen_cli.rpc_port,
        confgen_cli.p2p_port,
        proxy_port,
        confgen_cli.port_strategy,
        confgen_cli.listen_address,
        confgen_cli.outdir,
        confgen_cli.stub,
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

pub fn create_and_save_stub_config(outdir: PathBuf, peers: Vec<PeerP2PInfo>) -> Result<(), String> {


    info!("Writing stub configuration file to disk");
    let stub_config = P2PConfig::new(peers).unwrap();

    info!("Writing client configuration to disk");
    save_config_on_file(outdir, &stub_config, "stub.json".to_string()).expect("Error writing on stub config on file!");

    Ok(())
}

fn save_config_on_file<T: ?Sized + Serialize>(outdir: PathBuf, config: &T, filename: String) -> Result<(), String>{
    info!("Writing client configuration to disk");
    let mut outfile = outdir.clone();
    outfile.push(filename);

    let data = match serde_json::to_string(config) {
        Ok(s) => s,
        Err(e) => return Err(format!("JSON serialization failed: {}", e)),
    };

    match fs::write(outfile.clone(), data) {
        Ok(_) => {}
        Err(e) => {
            return Err(format!("Failed to write to file: {}, {:?}", e, outfile.to_str()));
        }
    }
    Ok(())
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

fn generate_configs(
    ips: Vec<String>,
    ips_proxy_nodes: Option<Vec<String>>,
    rpc_port: u16,
    p2p_port: u16,
    proxy_port: Option<u16>,
    port_strategy: PortStrategy,
    listen_address: String,
    outdir: PathBuf,
    stub: bool,
    event_file: Option<PathBuf>,
) -> Result<(), String> {
    info!("Generating configuration structs");
    let peers: Vec<Peer> = ips
        .iter()
        .enumerate()
        .map(|(i, ip)| {
            let p2p_port = match port_strategy {
                PortStrategy::Consecutive => 
                    // More than 2^16 peers? What are we, an ISP?
                    p2p_port + u16::try_from(i+1).unwrap(),
                PortStrategy::Static => p2p_port,
            };

            Peer {
                // This will fail if we ever have more than 2^32 peers, but that is unlikely. :)
                id: u32::try_from(i+1).unwrap(),
                ip: String::from(ip),
                p2p_port,
            }
        })
        .collect();
    
    let mut ip_list = ips;
    if ips_proxy_nodes.clone().is_some(){
        ip_list = ips_proxy_nodes.clone().unwrap();
    }
    

    //Final configuration
    let configs: Vec<ServerConfig> = ip_list
        .iter()
        .enumerate()
        .map(|(i, ip)| {
            let rpc_port = match port_strategy {
                PortStrategy::Consecutive => 
                    // More than 2^16 peers? What are we, an ISP?
                    rpc_port + u16::try_from(i+1).unwrap(),
                PortStrategy::Static => rpc_port,
            };

            //Set optional values i proxy are used
            let mut proxy: Option<ProxyNode> = None;
            if ips_proxy_nodes.clone().is_some() && proxy_port.clone().is_some(){
                
                let proxy_port = match port_strategy {
                    PortStrategy::Consecutive => 
                        // More than 2^16 peers? What are we, an ISP?
                        if stub{
                            // in case we are using the stub we have a central node acting as proxy
                            // we need the same port
                            proxy_port.unwrap()
                        }else{
                            proxy_port.unwrap() + u16::try_from(i+1).unwrap()
                        },
                    PortStrategy::Static => proxy_port.unwrap(),
                };

                proxy = Some((ProxyNode { ip: ip.to_string(), port: proxy_port}));
            }

            ServerConfig::new(
                u32::try_from(i+1).unwrap(),
                listen_address.clone(),
                rpc_port,
                peers.clone(),
                proxy, //TODO: consider also for the proxy_port the PortStrategy (the stub has the same port)
                event_file.clone(),
            )
            .unwrap()
        })
        .collect();

    info!("Writing configurations to disk");
    for cfg in configs {
        let mut outfile = outdir.clone();
        info!("Writing client configuration to disk");
        save_config_on_file(outfile, &cfg, format!("server_{:?}.json", cfg.id)).expect("Error writing server config on file!");
    }

    let p2p_peers: Vec<PeerP2PInfo> = peers.clone()
    .iter()
    .enumerate()
    .map(|(_, peer_ref)| {
        let peer = peer_ref.clone();
        PeerP2PInfo {
            id: peer.id,
            ip: peer.ip,
            p2p_port: peer.p2p_port,
        }
    })
    .collect();

    if stub {
        let mut outfile = outdir.clone();
        match create_and_save_stub_config(outfile, p2p_peers){
            Ok(_) => {},
            Err(e) => {
                return Err(format!("Failed to call create_and_save_stub_config. Error: {}", e));
            }
        }
    }

    // Code for generating the config for the client
    // TODO: substitute with a single function, try to not have to different function for the 2 configurations, or in general try to minimize replicated code. 

    let public_peers: Vec<PeerPublicInfo> = peers
        .iter()
        .enumerate()
        .map(|(i, peer_ref)| {
            let peer = peer_ref.clone();
            let rpc_port = match port_strategy {
                PortStrategy::Consecutive => 
                    // More than 2^16 peers? What are we, an ISP?
                    rpc_port + u16::try_from(i+1).unwrap(),
                PortStrategy::Static => rpc_port,
            };
            PeerPublicInfo {
                id: peer.id,
                ip: peer.ip,
                rpc_port: rpc_port,
            }
        })
        .collect();

    let client_config = ClientConfig::new(public_peers).unwrap();

    info!("Writing client configuration to disk");
    save_config_on_file(outdir, &client_config, "client.json".to_string()).expect("Error writing on client config on file!");

    Ok(())
}
