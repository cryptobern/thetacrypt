use std::error::Error;
use std::io;
use log::debug;

// Tokio 
use tokio::net::{TcpStream, TcpListener};
use tokio::io::{AsyncWriteExt, Interest};
use tokio::sync::mpsc::{Receiver, Sender};

// Thetacrypt
use crate::config::static_net::config_service::*;
use crate::types::message::P2pMessage;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProxyConfig{
    pub listen_addr: String,
    pub p2p_port: u16,
    pub proxy_addr: String,
    // add proxy port
}

pub async fn init(
    outgoing_msg_receiver: Receiver<P2pMessage>,
    incoming_msg_sender: Sender<P2pMessage>,
    config: ProxyConfig, //create a config for this 
    my_id: u32,
) {

    // load listener address from config file
    let port = config.p2p_port.to_string();
    let mut listen_addr = config.listen_addr.clone() + ":";
    listen_addr.push_str(&port);

    // Start proxy server
    println!("[Connection-proxy] Start the server");
    // Bind the listener to the address
    let listener = TcpListener::bind(listen_addr).await.expect("Failed to bind the server");
    println!("[Connection-proxy] Server started ...");
        tokio::spawn(async move {
            proxy_handler(listener, incoming_msg_sender.clone()).await
        });
    
    // Handle Channel Receiver
    println!("[Connection-proxy] Start outgoing message forwarder");
    let cloned_config = config.clone();
    tokio::spawn(async move {
        outgoing_message_forwarder(outgoing_msg_receiver, cloned_config);
    });
    
}

pub async fn outgoing_message_forwarder(mut receiver: Receiver<P2pMessage>, config: ProxyConfig) -> io::Result<()> {
    loop{
        let addr = config.proxy_addr.clone();
        let msg = receiver.recv().await;
        tokio::spawn(async move {
            let Some(data) = msg else { return };
            debug!("NET: Sending a message");
            //here goes the tendermint ip
            let stream = TcpStream::connect(addr+":8080").await.unwrap();
            send_share(stream).await;
        }); 
    }
}

pub async fn proxy_handler(listener: TcpListener, sender: Sender<P2pMessage>) -> io::Result<()> {
    loop {
        // The second item contains the IP and port of the new connection.
        let (socket, _) = listener.accept().await.unwrap();
        let sender_cloned = sender.clone();
        tokio::spawn(async move {
            receive_share(socket, sender_cloned).await;    //multiple threads need to read from here
        });
    }
}

pub async fn send_share(mut connection: TcpStream) -> io::Result<()> {
    println!("[Connection-proxy Sender] Successfully connected to server in port 8080");

    let msg = b"Hello!";

    connection.write_all(msg).await?;
    println!("[connection-proxy Sender] Sent the share...");

    Ok(())
}

async fn receive_share(connection: TcpStream, sender: Sender<P2pMessage>) -> io::Result<()> {

    let mut buffer = [0; 4096];
    let ready = connection.ready(tokio::io::Interest::READABLE).await?;
    
    if ready.is_readable(){
        connection.try_read(&mut buffer);
    }

    println!("[Connection-proxy Receiver] Received msg") ;

    //Send on the channel 
    match sender.send(P2pMessage::from(buffer.to_vec())).await {
        Ok(_) => (), 
        Err(e) => println!(">> TEST: error send to network {e}"),
    }

    Ok(())
}