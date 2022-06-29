use std::error::Error;
use libp2p::{Multiaddr, multiaddr::Protocol};
use reqwest;
use crate::network_info::deserialize::{RPCResult, StatusResult};

use super::deserialize::NetInfoResult;

// send request to RPC endpoint of tendermint node
pub async fn get_tendermint_status(address: String) -> Result<RPCResult<StatusResult>, Box<dyn Error>> {
    let req_url = address + "/status";
    let response = reqwest::get(req_url).await?.json::<RPCResult<StatusResult>>().await?;
    Ok(response)
}

pub fn get_listen_addr(res: RPCResult<StatusResult>) -> Multiaddr {
    let mut local_node_listen_address = res.result.node_info.listen_addr;
    let mut iter = local_node_listen_address.chars();
    iter.by_ref().nth(5); // remove leading 5 characters to retrieve only the ip and port
    local_node_listen_address = iter.as_str().to_string();
    let v: Vec<&str> = local_node_listen_address.split(':').collect(); // separate ip and port
    let listen_ip = v[0];
    let listen_port = v[1];
    // construct valid MultiAddr
    let mut multi_addr_listen: Multiaddr = format!("{}{}", "/ip4/", listen_ip).parse().unwrap();
    multi_addr_listen.push(Protocol::Tcp(listen_port.parse::<u16>().unwrap()));
    multi_addr_listen
}

pub fn get_dial_addr(res: RPCResult<NetInfoResult>) -> Multiaddr {
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
    let dial_port = w[1];
    // construct valid MultiAddr
    let mut multi_addr_dial: Multiaddr = format!("{}{}", "/ip4/", dial_ip).parse().unwrap();
    multi_addr_dial.push(Protocol::Tcp(dial_port.parse::<u16>().unwrap()));
    multi_addr_dial
}