use libp2p::{Multiaddr, multiaddr::Protocol};
use std::{fs, process::exit};
use toml;

use crate::config::tendermint_net_config::deserialize::Config;
use crate::config::tendermint_net_config::deserialize::{RPCResult, StatusResult};
use crate::config::tendermint_net_config::rpc_requests::rpc_net_info::get_tendermint_net_info;
use crate::config::tendermint_net_config::rpc_requests::rpc_status::get_tendermint_status;

use super::deserialize::NetInfoResult;

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
    // let listen_port = get_p2p_port(config, my_peer_id);

    format!("{}{}", config.listen_address, config.p2p_port)
        .parse()
        .expect(&format!(">> NET: Fatal error: Could not open listen port {}.", config.p2p_port))
}

// return rpc listening address as Multiaddr from config file
pub fn get_rpc_listen_addr(config: &Config) -> Multiaddr {
    // let listen_port = get_p2p_port(config, my_peer_id);

    format!("{}{}", config.listen_address, config.rpc_port)
        .parse()
        .expect(&format!(">> NET: Fatal error: Could not open listen port {}.", config.rpc_port))
}

pub async fn get_node_ips(tendermint_rpc_addr: String) {
    // get node ips by local tendermint RPC request
    match get_tendermint_net_info(tendermint_rpc_addr.to_string()).await {
        Ok(res) => {
            // println!("{:#?}", response);
            let urls = get_node_urls(res).await;
            println!("urls: {:?}", urls);
            // println!("no. of other peers {:#?}", response.result.n_peers);
            // for peer in response.result.peers {
            //     println!("node id: {:#?}", peer.node_id);
            //     println!("node url: {:#?}", peer.url);
            // }
        },
        Err(err) => println!("Error: {}", err),
    }
}

pub async fn get_node_urls(res: RPCResult<NetInfoResult>) -> Vec<String>{
    let mut urls: Vec<String> = [].to_vec();
    for peer in res.result.peers {
        urls.push(peer.url);
    }
    return urls;
}

// fn get_tendermint_node_rpc_addr() -> String {
//     // test tendermint RPC endpoint /status with reqwest
//     match get_tendermint_status(test_addr.to_string()).await {
//         Ok(response) => {
//             println!("{:#?}", response);
//             println!("{:#?}", response.result);
//         },
//         Err(err) => println!("Error: {}", err),
//     }
// }

// converts listening address from tendermint RPC result into Multiaddr
pub fn get_listen_multiaddr(res: RPCResult<StatusResult>) -> Multiaddr {
    let mut local_node_listen_address = res.result.node_info.listen_addr;
    let mut iter = local_node_listen_address.chars();
    iter.by_ref().nth(5); // remove leading 5 characters to retrieve only the ip and port
    local_node_listen_address = iter.as_str().to_string();
    let v: Vec<&str> = local_node_listen_address.split(':').collect(); // separate ip and port
    let listen_ip = v[0];
    // let listen_port = v[1];
    let listen_port = "36666";
    // construct valid MultiAddr
    let mut multi_addr_listen: Multiaddr = format!("{}{}", "/ip4/", listen_ip).parse().unwrap();
    multi_addr_listen.push(Protocol::Tcp(listen_port.parse::<u16>().unwrap()));
    multi_addr_listen
}

// converts dialing address from tendermint RPC result into Multiaddr
pub fn get_dial_multiaddr(res: RPCResult<NetInfoResult>) -> Multiaddr {
    let mut peer_urls: Vec<String> = Vec::new();
    for peer in res.result.peers {
        peer_urls.push(peer.url);
    }
    let temp_dial_addr = &peer_urls[0]; // take first (or another) peer url in mconn-format (nodeId@)ip)
    let mut iter = temp_dial_addr.chars();
    iter.by_ref().nth(48); // remove leading 48 characters to retrieve only the ip
    let addr_iter = &iter.as_str().to_string();
    let w: Vec<&str> = addr_iter.split(':').collect(); // separate ip and port
    let dial_ip = w[0];
    // let dial_port = w[1];
    let dial_port = "36666";
    // construct valid MultiAddr
    let mut multi_addr_dial: Multiaddr = format!("{}{}", "/ip4/", dial_ip).parse().unwrap();
    multi_addr_dial.push(Protocol::Tcp(dial_port.parse::<u16>().unwrap()));
    multi_addr_dial
}