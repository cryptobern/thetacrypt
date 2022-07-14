use libp2p::multiaddr::{Multiaddr, Protocol};
use std::{fs, process::exit};
use toml;

use crate::config::deserialize::Config;

// load config file
pub fn load_config(path: String) -> Config {
    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("Could not read file `{}`", path);
            exit(1);
        }
    };

    let config: Config = match toml::from_str(&contents) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Unable to load data from `{}`", path);
            println!("################ {}", e);
            exit(1);
        }
    };
    return config;
}

// return listening address as Multiaddr from config file
pub fn get_listen_addr(config: &Config, my_peer_id: u32) -> Multiaddr {
    let listen_port = get_p2p_port(config, my_peer_id);

    format!("{}{}", config.servers.listen_address, listen_port)
        .parse()
        .expect(&format!(">> NET: Fatal error: Could not open listen port {}.", listen_port))
}

// return dialing address as Multiaddr from config file
pub fn get_dial_addr(config: &Config, peer_id: u32) -> Multiaddr {
    let ip_version = "/ip4/";

    let dial_ip = get_ip(config, peer_id);
    let dial_port = get_p2p_port(config, peer_id);

    // create Multiaddr from config data
    let dial_base_addr = format!("{}{}", ip_version, dial_ip);
    let mut dial_addr: Multiaddr = dial_base_addr.parse().unwrap();
    dial_addr.push(Protocol::Tcp(dial_port.try_into().unwrap()));
    return dial_addr;
}

// get port number from config file
pub fn get_p2p_port(config: &Config, peer_id: u32) -> u32 {
    let listn_port: u32 = 27000; // default port number

    for (k, id) in config.servers.ids.iter().enumerate() {
        if *id == peer_id {
            return config.servers.p2p_ports[k];
        }
    }
    return listn_port;
}

// get ip from config file
pub fn get_ip(config: &Config, peer_id: u32) -> String {
    let listn_port: String = "127.0.0.1".to_string(); // default ip

    for (k, id) in config.servers.ids.iter().enumerate() {
        if *id == peer_id {
            return config.servers.ips[k].to_string();
        }
    }
    return listn_port.to_string();
}