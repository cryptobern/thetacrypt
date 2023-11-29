use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use thetacrypt_blockchain_stub::proto::blockchain_stub::AtomicBroadcastRequest;
// Tokio
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender};

use thetacrypt_blockchain_stub::proto::blockchain_stub::{
    blockchain_stub_client::BlockchainStubClient, ForwardShareRequest,
};

// Thetacrypt
use crate::types::message::NetMessage;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub p2p_port: u16,
    pub proxy_addr: String,
    // add proxy port
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
        println!("[Connection-proxy] Start the server");
        let listener = TcpListener::bind(address)
            .await
            .expect("Failed to bind the server");
        println!("[Connection-proxy] Server started ...");
        proxy_handler(listener, incoming_msg_sender.clone()).await
    });

    // Handle Channel Receiver
    println!("[Connection-proxy] Start outgoing message forwarder");
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
            println!("[Proxy]: Receiving message from outgoing_channel");
            //here goes the target_platform ip
            // match TcpStream::connect(addr+":60000").await{
            //     Ok(stream) => send_share(stream, Vec::from(data)).await.unwrap(),
            //     Err(e) => print!(">> [outgoing_message_forwarder]: error send to connect to tendermint node: {e}"),
            // }
            match BlockchainStubClient::connect("http://localhost:60000").await {
                Ok(mut client) => {
                    println!("Id of the msg {}", data.instance_id.clone());

                    if data.is_total_order {
                        let request = AtomicBroadcastRequest {
                            id: data.instance_id.clone(),
                            data: Vec::from(data),
                        };

                        tokio::spawn(async move { client.atomic_broadcast(request).await });
                    } else {
                        let request = ForwardShareRequest {
                            data: Vec::from(data),
                        };

                        tokio::spawn(async move { client.forward_share(request).await });
                    }
                }
                Err(e) => println!("Error in opening the connection!: {}", e),
            }
        });
    }
}

//TODO: change this in the interface of the stub
pub async fn send_share(mut connection: TcpStream, data: Vec<u8>) -> io::Result<()> {
    println!("[Connection-proxy Sender] Successfully connected to server, port 60000");

    connection.write_all(data.as_slice()).await?;
    println!("[connection-proxy Sender] sent the share to Tendermint...");

    Ok(())
}

// Methods to handle the receving from the target platform acting as an external network
pub async fn proxy_handler(listener: TcpListener, sender: Sender<NetMessage>) -> io::Result<()> {
    loop {
        let (socket, _) = listener.accept().await.unwrap();
        let sender_cloned = sender.clone();
        tokio::spawn(async move {
            receive_share(socket, sender_cloned).await //multiple threads need to read from here
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
            println!("Buffer read is empty...");
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
        Ok(_) => println!(
            ">> [Sender on the incoming channel] Message sent to the protocol layer: {:?}",
            msg_received
        ),
        Err(e) => println!(">> TEST: error send to network {e}"),
    }
    Ok(())
}
