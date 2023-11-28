// Tokio
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

use log::{error, info};
use std::error::Error;
use std::io::{self, Read};
use std::str::FromStr;

use thetacrypt_blockchain_stub::proto::blockchain_stub::blockchain_stub_server::{
    BlockchainStub, BlockchainStubServer,
};
use thetacrypt_blockchain_stub::proto::blockchain_stub::{
    ForwardShareRequest, ForwardShareResponse,
};
use tonic::{transport::Server, Request, Response, Status};

// struct BlockchainStubConfig {
//     pub addr: String,
//     pub port: u16,
// }

// #[derive(Copy, Clone)]
// struct ThetacryptBlockchainStub {
//     // blockchain: Vec<T>, //queue
//     // broadcast_channel_receiver: mpsc::Receiver<T>,
// }

// #[tonic::async_trait] // needed to allow async function in the trait
// impl BlockchainStub for ThetacryptBlockchainStub {
//     async fn forward_share(&self, request: Request<ForwardShareRequest>) -> Result<Response<ForwardShareResponse>, Status> {
//         println!("[BlockchainStubServer] Received forward_share request: {:?}", request.into_inner().data);
//         Ok(Response::new(ForwardShareResponse{}))
//     }
// }

// impl ThetacryptBlockchainStub {
//     async fn start_and_run(&self, address: SocketAddr) -> io::Result<()> {
//         println!("[BlockchainStubServer]: Request handler is starting. Listening for RPC on address: {address}");
//         Server::builder()
//             .add_service(BlockchainStubServer::new(*self))
//             // .serve(format!("[{rpc_listen_address}]:{rpc_listen_port}").parse().unwrap())
//             .serve(address)
//             .await
//             .expect("Error starting the gRPC Server!");
//     Ok(())
// }

// }

// // It will mantain the connections from the theta nodes and forward the messages (like a dispatcher)
// struct ProxyStub {
//     nodes_addrs: Vec<SocketAddr>,
// }

// // trait BlockchainFn{
// //     todo!(),
// // }

// struct ProxyListenerServer {}

// pub struct BlockchainStubListenerServer {
//     address: SocketAddr,
// }

// impl BlockchainStubListenerServer {
//     pub fn new(address: SocketAddr) -> Self {
//         BlockchainStubListenerServer { address }
//     }
// }

// pub struct Peer {}

// pub async fn forward_to_peers(_data: Vec<u8>, _peers: Vec<Peer>) -> io::Result<()> {
//     todo!()
// }

// pub async fn start_and_run(server: &BlockchainStubListenerServer) -> io::Result<()> {
//     // Server
//     println!("[BlockchainStubListenerServer] Start the server");
//     // Bind the listener to the address
//     let listener = TcpListener::bind(server.address).await?;
//     println!("[BlockchainStubListenerServer] Server started ...");
//     loop{
//         match listener.accept().await {
//             Ok((mut socket, addr)) => {
//                 println!("new client: {:?}", addr);
//                 //pass the handling to a thread
//                 tokio::spawn(async move{
//                     handle_incoming_request(&mut socket).await
//                 });
//             }
//             Err(e) => {
//                 println!("couldn't get client: {:?}", e);
//                 return Err(e);
//             }
//         }
//     }
// }

// async fn handle_incoming_request(socket: &mut TcpStream) -> io::Result<()> {
//     //code to open the message and handle it
//     let mut buf = vec![0; 1]; //See how big we need the buffer and if we can read until is empty and concatenate evrything togeher
//     let mut data: Vec<u8> = Vec::new();
//     loop {
//         let n = socket
//             .read(&mut buf)
//             .await?;

//         if n == 0 {
//             println!("Buffer read is empty...");
//             break; //This is needed to exit the loop and terminate this thread
//         }

//         if buf[0] == 0 {
//             break;
//         }

//         // connection
//         //     .write_all(&buf[0..n])
//         //     .await
//         //     .expect("failed to write data to socket");
//         data.append(&mut buf.to_vec());
//         //Send on the channel
//         // forward_to_peers(data, peers)
//     }

//     println!("Msg received on the thread: {:?}", data);

//     // TODO: Once we read the message we just need to forwarded to the other parties
//     Ok(())
// }

// async fn listener_thread<T>(listener: TcpListener, sender: mpsc::Sender<T>) {
//     loop {
//         // The second item contains the IP and port of the new connection.
//         let (socket, remote_addr) = listener.accept().await.unwrap();
//         let sender_cloned = sender.clone();
//         tokio::spawn(async move {
//             // receive_share(socket, remote_addr, sender_cloned).await
//         });
//     }
// }

#[tokio::main]
async fn main() -> io::Result<()> {
    println!("Hello Blockchain Stub");

    // //network information
    // let host = "127.0.0.1";
    // let host_ip = <Ipv4Addr>::from_str(host).unwrap();
    // let port: u16 = 50000;
    // let address = SocketAddr::new(IpAddr::V4(host_ip), port);

    // // // Struct to handle the blockchain stub
    // // let blockchain_server= BlockchainStubListenerServer::new(address);

    // // start_and_run(&blockchain_server).await

    // let service = ThetacryptBlockchainStub{};

    // tokio::spawn(async move{
    //     println!("Server is starting");
    //     service.start_and_run(address).await
    // });

    // info!("Server is running");
    // tokio::select! {
    //     _ = tokio::signal::ctrl_c() => {
    //         println!("Received interrupt signal, shutting down");
    //         Ok(())
    //     }
    // }

    Ok(())
    // //Create the broadcast channel for communicating with the blockchain data structure
    // let (b_sender, b_receiver) = mpsc::channel::<Vec<u8>>(32);

    // Start the server
    // Initialize the data structure for the blockchain
    // Handle the listener so that every request is handled by modifying the state of the blockchain atomically
    // All the messages sent to the blockchain must be totally ordered. So it doesn't matter the order in which they arrive, but in the deliver phase (when we are triggered on the node about something decided in the blockchain we need to ensure that every node will receive the same messages in the same order). How can we do this? We can keep a list of teh connected endpoints and for each of them keeping a thread that notifies and points to a particular position of the vector. Modifying it just if the reception of th message was ack(ed).
}

// async fn connect_to_all_local(config: ClientConfig) -> Vec<ThresholdCryptoLibraryClient<tonic::transport::Channel>> {
//     let mut connections = Vec::new();
//     for peer in config.peers.iter() {
//         let ip = peer.ip.clone();
//         let port = peer.rpc_port;
//         let addr = format!("http://[{ip}]:{port}");
//         connections.push(
//             ThresholdCryptoLibraryClient::connect(addr.clone())
//                 .await
//                 .unwrap(),
//         );
//     }
//     println!(">> Established connection to network.");
//     connections
// }
