use libp2p::multiaddr::{Multiaddr, Protocol};
use std::env;
use std::net::Ipv4Addr;
use std::str::FromStr;

use crate::config::static_net::deserialize::Config;

// load config file
pub fn load_config() -> Config {
    let number_of_nodes = match env::var("NUMBER_OF_NODES") {
        Ok(number_of_nodes) => number_of_nodes,
        Err(e) => panic!("Couldn't read NUMBER_OF_NODES ({:?})", e),
    };

    let base_address = match env::var("BASE_ADDRESS") {
        Ok(base_address) => base_address,
        Err(e) => panic!("Couldn't read base_ip ({:?})", e),
    };

    let p2p_port = match env::var("P2P_PORT") {
        Ok(p2p_port) => p2p_port,
        Err(e) => panic!("Couldn't read P2P_PORT ({:?})", e),
    };

    let rpc_port = match env::var("RPC_PORT") {
        Ok(rpc_port) => rpc_port,
        Err(e) => panic!("Couldn't read RPC_PORT ({:?})", e),
    };

    let base_listen_address = String::from("/ip4/0.0.0.0/tcp/");

    let mut ids: Vec<u32> = Vec::new();
    let mut ips: Vec<String> = Vec::new();

    for i in 0..number_of_nodes.parse::<usize>().unwrap() {
        ids.push((i + 1) as u32);
        ips.push(build_ip_from_base(&base_address.to_string(), (i + 2) as u8));
    }

    let peer_count: u16 = u16::try_from(ips.len()).unwrap();
    // This function only supports specifying a single port for all peers, via env variable. So
    // we'll store the same port for all peers.
    let config = Config {
        ids,
        ips,
        p2p_ports: vec![p2p_port.parse::<u16>().unwrap(), peer_count],
        rpc_ports: vec![rpc_port.parse::<u16>().unwrap(), peer_count],
        base_listen_address,
    };

    // let contents = match fs::read_to_string(&path) {
    //     Ok(c) => c,
    //     Err(_) => {
    //         eprintln!("Could not read file `{}`", path);
    //         exit(1);
    //     }
    // };

    // let config: Config = match toml::from_str(&contents) {
    //     Ok(d) => d,
    //     Err(e) => {
    //         eprintln!("Unable to load data from `{}`", path);
    //         println!("################ {}", e);
    //         exit(1);
    //     }
    // };
    return config;
}

// return p2p listening address as Multiaddr from config file
pub fn get_p2p_listen_addr(config: &Config, my_peer_id: u32) -> Multiaddr {
    let p2p_listen_port = get_p2p_port(config, my_peer_id);

    format!("{}{}", config.base_listen_address, p2p_listen_port)
        .parse()
        .expect(&format!(
            ">> NET: Fatal error: Could not open P2P listen port {}.",
            p2p_listen_port
        ))
}

// return rpc listening address as Multiaddr from config file
pub fn get_rpc_listen_addr(config: &Config, my_peer_id: u32) -> Multiaddr {
    let rpc_listen_port = get_rpc_port(config, my_peer_id);

    format!("{}{}", config.base_listen_address, rpc_listen_port)
        .parse()
        .expect(&format!(
            ">> NET: Fatal error: Could not open RPC listen port {}.",
            rpc_listen_port
        ))
}

// return dialing address as Multiaddr from config file
pub fn get_dial_addr(config: &Config, peer_id: u32) -> Multiaddr {
    let ip_version = "/ip4/";

    let dial_ip = get_ip(config, peer_id);
    let dial_port = get_p2p_port(config, peer_id);

    // create Multiaddr from config data
    let dial_base_addr = format!("{}{}", ip_version, dial_ip);
    let mut dial_addr: Multiaddr = dial_base_addr.parse().unwrap();
    dial_addr.push(Protocol::Tcp(dial_port));
    return dial_addr;
}

// get p2p port from config file
fn get_p2p_port(config: &Config, peer_id: u32) -> u16 {
    let listn_port: u16 = 27000; // default port number

    for (k, id) in config.ids.iter().enumerate() {
        if *id == peer_id {
            return config.p2p_ports[k];
        }
    }

    return listn_port;
}

/// Get peer's P2P port from configuration based on its ID.
///
/// Returns default port of 27000 if no configuration found for this peer.
pub fn get_rpc_port(config: &Config, peer_id: u32) -> u16 {
    let listen_port: u16 = 27000; // default port number

    for (k, id) in config.ids.iter().enumerate() {
        if *id == peer_id {
            return config.rpc_ports[k];
        }
    }

    return listen_port;
}

/// Get peer's P2P IP from configuration based on its ID.
///
/// Returns default IP of 127.0.0.1 if no configuration found for this peer.
fn get_ip(config: &Config, peer_id: u32) -> String {
    let listen_ip: String = "127.0.0.1".to_string(); // default ip

    for (k, id) in config.ids.iter().enumerate() {
        if *id == peer_id {
            return config.ips[k].to_string();
        }
    }
    return listen_ip.to_string();
}

fn build_ip_from_base(base_address: &String, id: u8) -> String {
    let base_ip = match Ipv4Addr::from_str(base_address) {
        Ok(base_ip) => base_ip,
        Err(e) => panic!("Couldn't read base_ip ({:?})", e),
    };

    let base_ip_octects = Ipv4Addr::octets(&base_ip);
    let new_ip = Ipv4Addr::new(
        base_ip_octects[0],
        base_ip_octects[1],
        base_ip_octects[2],
        id,
    );
    return new_ip.to_string();
}
