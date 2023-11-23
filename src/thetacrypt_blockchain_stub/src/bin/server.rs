// Tokio
use log::info;
use std::io;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thetacrypt_blockchain_stub::proto::blockchain_stub::blockchain_stub_server::{
    BlockchainStub, BlockchainStubServer,
};
use thetacrypt_blockchain_stub::proto::blockchain_stub::{
    ForwardShareRequest, ForwardShareResponse,
};
use tonic::{transport::Server, Request, Response, Status};

/// PublicInfo to reach the server and its RPC endpoint.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerP2PInfo {
    pub id: u32,
    pub ip: String,
    pub p2p_port: u16,
}

/// Configuration of the server binary.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientConfig {
    pub peers: Vec<PeerP2PInfo>,
}

#[derive(Clone)]
struct ThetacryptBlockchainStub {
    peers: Vec<PeerP2PInfo>,
    // blockchain: Vec<T>, //queue
    // broadcast_channel_receiver: mpsc::Receiver<T>,
}

fn connect_to_all_local(config: ClientConfig) -> Vec<TcpStream> {
    let mut connections = Vec::new();
    for peer in config.peers.iter() {
        let ip = peer.ip.clone();
        let port = peer.p2p_port;
        let address = SocketAddr::new(IpAddr::V4(<Ipv4Addr>::from_str(&ip).unwrap()), port);
        let stream = TcpStream::connect(address).expect("Failed to connect");
        connections.push(stream);
    }
    println!(">> Established connection to network.");
    connections
}

#[tonic::async_trait] // needed to allow async function in the trait
impl BlockchainStub for ThetacryptBlockchainStub {
    async fn forward_share(
        &self,
        request: Request<ForwardShareRequest>,
    ) -> Result<Response<ForwardShareResponse>, Status> {
        //Forward to the other parties
        let peers_config = ClientConfig { peers: self.peers.clone() };
        let streams = connect_to_all_local(peers_config);

        let binding = request.into_inner();
        let msg = binding.data.as_slice();
        for mut stream in streams {
            let _write_all = stream.write_all(msg);
        }

        println!(
            "[BlockchainStubServer] Received forward_share request and send it to the other thetacrypt nodes!"
        );

        Ok(Response::new(ForwardShareResponse {}))
    }
}

impl ThetacryptBlockchainStub {}

async fn start_and_run(service: ThetacryptBlockchainStub, address: SocketAddr) -> io::Result<()> {
    println!("[BlockchainStubServer]: Request handler is starting. Listening for RPC on address: {address}");
    Server::builder()
        .add_service(BlockchainStubServer::new(service))
        // .serve(format!("[{rpc_listen_address}]:{rpc_listen_port}").parse().unwrap())
        .serve(address)
        .await
        .expect("Error starting the gRPC Server!");
    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    println!("Hello Blockchain Stub");

    //network address of teh stub
    let host = "127.0.0.1";
    let host_ip = <Ipv4Addr>::from_str(host).unwrap();
    let port: u16 = 60000;
    let address = SocketAddr::new(IpAddr::V4(host_ip), port);

    // Hardcoded addresses of the peers just for test
    // TODO: read these information from a config file
    let p2p_info_1 = PeerP2PInfo {
        id: 1,
        ip: "127.0.0.1".to_string(),
        p2p_port: 50000,
    };
    let p2p_info_2 = PeerP2PInfo {
        id: 2,
        ip: "127.0.0.1".to_string(),
        p2p_port: 50001,
    };
    let p2p_info_3 = PeerP2PInfo {
        id: 3,
        ip: "127.0.0.1".to_string(),
        p2p_port: 50002,
    };
    let p2p_info_4 = PeerP2PInfo {
        id: 4,
        ip: "127.0.0.1".to_string(),
        p2p_port: 50003,
    };

    let peers = vec![p2p_info_1, p2p_info_2, p2p_info_3, p2p_info_4];
    let service = ThetacryptBlockchainStub { peers: peers };

    tokio::spawn(async move {
        println!("Server is starting");
        start_and_run(service, address).await
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
