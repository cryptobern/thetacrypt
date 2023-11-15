// Tokio
use std::net::{IpAddr, Ipv4Addr, SocketAddr};


use std::io;
use std::str::FromStr;
use log::info;

use tonic::{transport::Server, Request, Response, Status};
use thetacrypt_blockchain_stub::proto::blockchain_stub::blockchain_stub_server::{BlockchainStubServer, BlockchainStub};
use thetacrypt_blockchain_stub::proto::blockchain_stub::{ForwardShareRequest, ForwardShareResponse};


#[derive(Copy, Clone)]
struct ThetacryptBlockchainStub {
    // blockchain: Vec<T>, //queue
    // broadcast_channel_receiver: mpsc::Receiver<T>,
}

#[tonic::async_trait] // needed to allow async function in the trait 
impl BlockchainStub for ThetacryptBlockchainStub {
    async fn forward_share(&self, request: Request<ForwardShareRequest>) -> Result<Response<ForwardShareResponse>, Status> {
        println!("[BlockchainStubServer] Received forward_share request: {:?}", request.into_inner().data);
        Ok(Response::new(ForwardShareResponse{}))
    }
}


impl ThetacryptBlockchainStub {
    async fn start_and_run(&self, address: SocketAddr) -> io::Result<()> {
        println!("[BlockchainStubServer]: Request handler is starting. Listening for RPC on address: {address}");
        Server::builder()
            .add_service(BlockchainStubServer::new(*self))
            // .serve(format!("[{rpc_listen_address}]:{rpc_listen_port}").parse().unwrap())
            .serve(address)
            .await
            .expect("Error starting the gRPC Server!");
    Ok(())
}

}

#[tokio::main]
async fn main() -> io::Result<()> {
    println!("Hello Blockchain Stub");

    //network information
    let host = "127.0.0.1";
    let host_ip = <Ipv4Addr>::from_str(host).unwrap();
    let port: u16 = 50000;
    let address = SocketAddr::new(IpAddr::V4(host_ip), port);

    let service = ThetacryptBlockchainStub{};

    tokio::spawn(async move{
        println!("Server is starting");
        service.start_and_run(address).await
    });

    info!("Server is running");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Received interrupt signal, shutting down");
            Ok(())
        }
    }


    // //Create the broadcast channel for communicating with the blockchain data structure
    // let (b_sender, b_receiver) = mpsc::channel::<Vec<u8>>(32);

    // Start the server
    // Initialize the data structure for the blockchain
    // Handle the listener so that every request is handled by modifying the state of the blockchain atomically
    // All the messages sent to the blockchain must be totally ordered. So it doesn't matter the order in which they arrive, but in the deliver phase (when we are triggered on the node about something decided in the blockchain we need to ensure that every node will receive the same messages in the same order). How can we do this? We can keep a list of teh connected endpoints and for each of them keeping a thread that notifies and points to a particular position of the vector. Modifying it just if the reception of th message was ack(ed).
}
