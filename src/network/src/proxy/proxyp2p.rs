use std::io;
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

use crate::interface::Gossip;
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

pub struct ProxyP2P {
    pub config: ProxyConfig,
    pub id: u32,
}

#[async_trait]
impl Gossip for ProxyP2P {

    type T = NetMessage;
    fn broadcast(&mut self, message: NetMessage) {
        todo!()
    }


    async fn deliver(&mut self) -> Option<NetMessage> {
        todo!()
    }
}

pub async fn init(
    outgoing_msg_receiver: Receiver<NetMessage>,
    incoming_msg_sender: Sender<NetMessage>,
    config: ProxyConfig, //create a config for this
    my_id: u32,
) -> io::Result<()> {
    //create the listening address to listen for messages from the p2p
    let host_ip = <Ipv4Addr>::from_str(config.listen_addr.as_str()).unwrap();
    let port: u16 = config.p2p_port;
    let address = SocketAddr::new(IpAddr::V4(host_ip), port);

    // Start proxy server
    tokio::spawn(async move {
        info!("Start the server");
        let listener = TcpListener::bind(address)
            .await
            .expect("Failed to bind the server");
        info!("Server started ...");
        proxy_handler(listener, incoming_msg_sender.clone()).await
    });

    // Handle Channel Receiver
    info!("Start outgoing message forwarder");
    let cloned_config = config.clone();
    tokio::spawn(async move {
        outgoing_message_forwarder(outgoing_msg_receiver, cloned_config).await //the receiver can't be cloned
    });
    Ok(())
}

pub async fn outgoing_message_forwarder(
    mut receiver: Receiver<NetMessage>,
    config: ProxyConfig,
) -> io::Result<()> {
    loop {
        let addr = config.proxy_addr.clone();
        let msg = receiver.recv().await;
        tokio::spawn(async move {
            let Some(data) = msg else { return };
            info!("Receiving message from outgoing_channel");
            //here goes the target_platform ip
            let mut address = addr.to_owned();
            address.push(':');
            address.push_str(&config.proxy_port.to_string());
            info!("Connecting to remote address: {}", address);
            match TcpStream::connect(address).await{
                Ok(stream) => send_share(stream, Vec::from(data)).await.unwrap(),
                Err(e) => error!(">> Error connecting to blockchain node: {e}"),
            }

            // match BlockchainStubClient::connect(address).await {
            //     Ok(mut client) => {
            //         println!("Id of the msg {}", data.instance_id.clone());

            //         if data.is_total_order {
            //             let request = AtomicBroadcastRequest {
            //                 id: data.instance_id.clone(),
            //                 data: Vec::from(data),
            //             };

            //             tokio::spawn(async move { client.atomic_broadcast(request).await });
            //         } else {
            //             let request = ForwardShareRequest {
            //                 data: Vec::from(data),
            //             };

            //             tokio::spawn(async move { client.forward_share(request).await });
            //         }
            //     }
            //     Err(e) => println!("Error in opening the connection!: {}", e),
            // }
        });
    }
}

pub async fn send_share(mut connection: TcpStream, data: Vec<u8>) -> io::Result<()> {
    info!("Successfully connected to server");

    connection.write_all(data.as_slice()).await?;
    info!(" >> Share sent to Blockchain...");

    Ok(())
}

//Methods to handle the receving from thetacrypt
pub async fn proxy_handler(listener: TcpListener, sender: Sender<NetMessage>) -> io::Result<()> {
    loop {
        let (socket, _remote_addr) = listener.accept().await.unwrap();
        let sender_cloned = sender.clone();
        tokio::spawn(async move {
            let _ = receive_share(socket, sender_cloned).await; //multiple threads need to read from here
        });
    }
}

//This should work because every time tendermint needs to send a share it opens a different connection
async fn receive_share(mut connection: TcpStream, sender: Sender<NetMessage>) -> io::Result<()> {
    let mut buf = vec![0; 1]; //See how big we need the buffer and if we can read until is empty and concatenate evrything togeher
    let mut data: Vec<u8> = Vec::new();
    loop {
        let n = connection
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

        // connection
        //     .write_all(&buf[0..n])
        //     .await
        //     .expect("failed to write data to socket");
        data.append(&mut buf.to_vec());
        // println!("Appending something to the vector!"); //test if this goes in idle
        //Send on the channel
    }
    let data_cloned = data.clone();
    let msg_received = NetMessage::from(data_cloned);
    let msg = NetMessage::from(data);
    match sender.send(msg).await {
        Ok(_) => info!(
            ">> Message with instance_id {:?} sent to the protocol layer. ",
            msg_received.get_instace_id()
        ),
        Err(e) => error!(">> TEST: error send to network {e}"),
    }
    Ok(())
}
