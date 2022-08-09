use libp2p::{Multiaddr, multiaddr::Protocol};
use std::{fs, process::exit};
use toml;

use crate::config::tendermint_net::deserialize::Config;
use super::rpc_requests::net_info::get_tendermint_net_info;
use super::rpc_requests::status::get_tendermint_status;

const TENDERMINT_RPC_ADDR: &str = "http://127.0.0.1:26657";

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

// return p2p listening address as Multiaddr from config file
pub fn get_p2p_listen_addr(config: &Config) -> Multiaddr {
    format!("{}{}", config.p2p_base_listen_address, config.p2p_port)
        .parse()
        .expect(&format!(">> NET: Fatal error: Could not open listen port {}.", config.p2p_port))
}

// return ips from all other tendermint nodes
pub async fn get_node_ips() -> Vec<String> {
    // get node ips by local tendermint RPC request
    let mut ips: Vec<String> = Vec::new();
    //-------ROSE-CHANGES------------
    // match get_tendermint_net_info(TENDERMINT_RPC_ADDR.to_string()).await {
    //     Ok(res) => {
    //         for peer in res.result.peers {
    //             let url = peer.url;
    //             // get ip from urls
    //             let ip = &url[49..61];
    //             ips.push(ip.to_string());
    //         }
    //         return ips;
    //     },
    //     Err(err) => println!("Error: {}", err),
    // }
    ips.push(String::from("node1"));
    ips.push(String::from("node2"));
    ips.push(String::from("node3"));
    ips.push(String::from("node4"));
    return ips;
}

// return ids from all other tendermint nodes
pub async fn get_node_ids() -> Vec<String> {
    // get node ips by local tendermint RPC request
    // let tendermint_rpc_addr = "http://127.0.0.1:26657";
    let mut ips: Vec<String> = Vec::new();
    match get_tendermint_net_info(TENDERMINT_RPC_ADDR.to_string()).await {
        Ok(res) => {
            for peer in res.result.peers {
                let url = peer.url;
                // get ids from urls
                let id = &url[8..48];
                ips.push(id.to_string());
            }
            return ips;
        },
        Err(err) => println!("Error: {}", err),
    }
    return ips;
}

// return dialing address as Multiaddr for corresponding peer id
pub fn get_dial_addr(dial_port: u16, dial_ip: String) -> Multiaddr {
    let ip_version = "/ip4/";
    // let dial_port = config.p2p_port;

    // create Multiaddr
    let dial_base_addr = format!("{}{}", ip_version, dial_ip);
    let mut dial_addr: Multiaddr = dial_base_addr.parse().unwrap();
    dial_addr.push(Protocol::Tcp(dial_port));
    return dial_addr;
}

// get id from local node
pub async fn get_tendermint_node_id() -> String {
    let mut node_id: String = "".to_string();
    // test tendermint RPC endpoint /status with reqwest
    match get_tendermint_status(TENDERMINT_RPC_ADDR.to_string()).await {
        Ok(res) => {
            node_id = res.result.node_info.id;
            // println!("{:#?}", res);
            // println!("{:#?}", res.result);
        },
        Err(err) => println!("Error: {}", err),
    }
    return node_id;
}

// get rpc base address
pub fn get_rpc_base_address(config: &Config) -> String {
    let rpc_base_addr = &config.rpc_base_listen_address;
    return rpc_base_addr.to_string();
}

// get rpc base address
pub fn get_rpc_port(config: &Config) -> u16 {
    let rpc_port = &config.rpc_port;
    return *rpc_port;
}