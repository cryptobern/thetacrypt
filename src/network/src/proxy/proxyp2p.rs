use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use log::{info, error, debug};
use thetacrypt_blockchain_stub::proto::blockchain_stub::AtomicBroadcastRequest;
// Tokio
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender};

use thetacrypt_blockchain_stub::proto::blockchain_stub::{
    blockchain_stub_client::BlockchainStubClient, ForwardShareRequest,
};

use crate::interface::{Gossip, TOB};
// Thetacrypt
use crate::types::message::NetMessage;

use serde::{Deserialize, Serialize};

use tonic::async_trait;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub p2p_port: u16,
    pub proxy_addr: String,
    pub proxy_port: u16,
}

pub struct ProxyP2PStub {
    pub config: ProxyConfig,
    pub id: u32,
    pub listener: Option<TcpListener>,
}

#[async_trait]
impl Gossip<NetMessage> for ProxyP2PStub {
    fn broadcast(&mut self, message: NetMessage) {
        info!("Receiving message from outgoing_channel");
        //here goes the target_platform ip
        let mut address = self.config.proxy_addr.clone().to_owned();
        address.push(':');
        address.push_str(&self.config.proxy_port.to_string());
        info!("Connecting to remote address: {}", address);
        tokio::spawn(async move {
            match BlockchainStubClient::connect(address).await {
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

impl ProxyP2PStub {

    pub fn new(config: ProxyConfig, id: u32) -> Self {
        return ProxyP2PStub { config: config, id: id , listener: None}
    }

    pub async fn start_service(&mut self) {

        let host_ip = <Ipv4Addr>::from_str(self.config.listen_addr.as_str()).unwrap();
        let port: u16 = self.config.p2p_port;
        let address = SocketAddr::new(IpAddr::V4(host_ip), port);

        info!("Start ProxyP2PStub");
        let listener = TcpListener::bind(address)
            .await
            .expect("Failed to bind the server");
        info!("ProxyP2PStub started ...");
        self.listener = Some(listener);
    }
}

pub struct ProxyTOBStub {
    pub config: ProxyConfig,
    pub id: u32,
}

#[async_trait]
impl TOB<NetMessage> for ProxyTOBStub {
    fn broadcast(&mut self, message: NetMessage){
        info!("Receiving message from outgoing_channel");
        //here goes the target_platform ip
        let mut address = self.config.proxy_addr.clone().to_owned();
        address.push(':');
        address.push_str(&self.config.proxy_port.to_string());
        info!("Connecting to remote address: {}", address);
        tokio::spawn(async move {
            match BlockchainStubClient::connect(address).await {
                Ok(mut client) => {
                    println!("Id of the msg {}", message.get_instace_id().clone());
                    let request = AtomicBroadcastRequest {
                        id: message.get_instace_id().to_string(),
                        data: Vec::from(message),
                    };

                    tokio::spawn(async move { client.atomic_broadcast(request).await });
                }
                Err(e) => println!("Error in opening the connection!: {}", e),
            }
        });
    }
    async fn deliver(&self) -> Option<NetMessage>{
        todo!() //poll the blockchain state
    }
}


impl ProxyTOBStub {

    pub fn new(config: ProxyConfig, id: u32) -> Self {
        return ProxyTOBStub{
            config,
            id,
        }
    }

    //setup of service listening for incoming messages
    fn start_service(){
        todo!()
    }
}

