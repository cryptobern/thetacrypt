// Tokio
use log::{error, info};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::io;
use std::process::exit;

use thetacrypt_blockchain_stub::proto::blockchain_stub::blockchain_stub_server::{
    BlockchainStub, BlockchainStubServer,
};
use thetacrypt_blockchain_stub::proto::blockchain_stub::{
    ForwardShareRequest, ForwardShareResponse,
};
use tonic::{transport::Server, Request, Response, Status};

use thetacrypt_blockchain_stub::cli::cli::P2PCli;
use thetacrypt_blockchain_stub::cli::types::{P2PConfig, PeerP2PInfo};
use clap::Parser;

#[derive(Clone)]
struct ThetacryptBlockchainStub {
    peers: Vec<PeerP2PInfo>,
    // blockchain: Vec<T>, //queue
    // broadcast_channel_receiver: mpsc::Receiver<T>,
}

fn connect_to_all_local(config: P2PConfig) -> Vec<TcpStream> {
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
        let peers_config = P2PConfig {
            peers: self.peers.clone(),
        };
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

    // loading the configuration about the peer from file
    let client_cli = P2PCli::parse();

    info!(
        "Loading configuration from file: {}",
        client_cli
            .config_file
            .to_str()
            .unwrap_or("Unable to print path, was not valid UTF-8"),
    );
    let config = match P2PConfig::from_file(&client_cli.config_file) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("{}", e);
            exit(1);
        }
    };

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

    let _peers = vec![p2p_info_1, p2p_info_2, p2p_info_3, p2p_info_4];

    // Here now we use the PeerInfo coming from config file
    let service = ThetacryptBlockchainStub { peers: config.peers };

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
