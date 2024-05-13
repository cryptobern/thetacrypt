use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use log::{info, error, debug};
use theta_proto::proxy_api::AtomicBroadcastRequest;
// Tokio
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender};

use theta_proto::proxy_api::{
    proxy_api_client::ProxyApiClient, ForwardShareRequest,
};

use crate::interface::{Gossip, TOB};
use crate::types::config::NetworkConfig;
// Thetacrypt
use crate::types::message::NetMessage;

use serde::{Deserialize, Serialize};

use tonic::async_trait;

pub struct P2PProxy {
    pub config: NetworkConfig,
    pub id: u32,
    listener: Option<TcpListener>,
}

#[async_trait]
impl Gossip for P2PProxy {

    type T = NetMessage;
    fn broadcast(&mut self, message: NetMessage) {
        info!("Receiving message from outgoing_channel");
        //here goes the target_platform ip

        let proxy_node = self.config.proxy.as_ref().unwrap().clone();
        let port: u16 = proxy_node.port;
        let ip = proxy_node.ip;

        let address: String = format!("http://{}:{}",ip, port)
        .parse()
        .expect(&format!(
            ">> Fatal error: Could not format address for ip:{}, and port {}.",
            ip,
            port
        ));

        info!("Connecting to remote address: {}", address);
        tokio::spawn(async move {
            match ProxyApiClient::connect(address).await {
                Ok(mut client) => {
                    println!("Id of the msg {}", message.get_instace_id().clone());
                    let request = ForwardShareRequest {
                        data: Vec::from(message),
                    };

                    tokio::spawn(async move { client.forward_share(request).await });
                }
                Err(e) => println!("Error in opening the connection!: {}", e),
            }
        });
    }

    async fn deliver(&mut self) -> Option<NetMessage> {
        let (mut socket, _remote_addr) = self.listener.as_ref().unwrap().accept().await.unwrap();
        let mut buf = vec![0; 1]; //See how big we need the buffer and if we can read until is empty and concatenate evrything togeher
        let mut data: Vec<u8> = Vec::new();
        loop {
            let n = socket
                .read(&mut buf)
                .await
                .expect("failed to read data from socket");
            if n == 0 {
                debug!("Buffer read is empty...");
                break; //This is needed to exit the loop and terminate this thread
            }
            if buf[0] == 0 {
                break;
            }
            data.append(&mut buf.to_vec());
        }
        let msg = NetMessage::from(data);
        return Some(msg)
    }
}

impl P2PProxy {

    pub fn new(config: NetworkConfig, id: u32) -> Self {
        return P2PProxy { config: config, id: id , listener: None}
    }

    pub async fn init(&mut self) {

        let local_node = self.config.local_peer.clone();

        let host_ip = <Ipv4Addr>::from_str(local_node.ip.as_str()).unwrap();
        let port: u16 = local_node.port;
        let address = SocketAddr::new(IpAddr::V4(host_ip), port);

        info!("Start ProxyP2PStub");
        let listener = TcpListener::bind(address)
            .await
            .expect("Failed to bind the server");
        info!("P2PProxy started ...");
        self.listener = Some(listener);
    }
}

//TODO: finish the implementation deciding if it is the blockchain part that should push when something is decided (maybe here consider the finality)
pub struct ProxyTOBStub {
    pub config: NetworkConfig,
    pub id: u32,
}

// #[async_trait]
// impl TOB for ProxyTOBStub {

//     type T = NetMessage;

//     fn broadcast(&mut self, message: Self::T){
//         info!("Receiving message from outgoing_channel");
//         //here goes the target_platform ip
//         let mut address = self.config.proxy_addr.clone().to_owned();
//         address.push(':');
//         address.push_str(&self.config.proxy_port.to_string());
//         info!("Connecting to remote address: {}", address);
//         tokio::spawn(async move {
//             match BlockchainStubClient::connect(address).await {
//                 Ok(mut client) => {
//                     println!("Id of the msg {}", message.get_instace_id().clone());
//                     let request = AtomicBroadcastRequest {
//                         id: message.get_instace_id().to_string(),
//                         data: Vec::from(message),
//                     };

//                     tokio::spawn(async move { client.atomic_broadcast(request).await });
//                 }
//                 Err(e) => println!("Error in opening the connection!: {}", e),
//             }
//         });
//     }
//     async fn deliver(&self) -> Option<Self::T>{
//         todo!() //poll the blockchain state
//     }
// }


impl ProxyTOBStub {

    pub fn new(config: NetworkConfig, id: u32) -> Self {
        return ProxyTOBStub{
            config,
            id,
        }
    }

    //setup of service listening for incoming messages
    fn init(){
        todo!()
    }
}

