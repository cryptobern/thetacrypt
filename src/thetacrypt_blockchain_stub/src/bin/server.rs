// Tokio
use log::{error, info};
use std::collections::{HashSet, VecDeque};
use std::io;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::process::exit;
use std::str::FromStr;
use tokio::sync::mpsc;

use thetacrypt_blockchain_stub::proto::blockchain_stub::blockchain_stub_server::{
    BlockchainStub, BlockchainStubServer,
};
use thetacrypt_blockchain_stub::proto::blockchain_stub::{
    AtomicBroadcastRequest, AtomicBroadcastResponse, ForwardShareRequest, ForwardShareResponse,
};
use tonic::{transport::Server, Request, Response, Status};

use clap::Parser;
use thetacrypt_blockchain_stub::cli::cli::P2PCli;
use thetacrypt_blockchain_stub::cli::types::{P2PConfig, PeerP2PInfo};

const MAX_BLOCKCHAIN_CAPACITY: usize = 100;
#[derive(Clone)]
struct ThetacryptBlockchainStub {
    peers: Vec<PeerP2PInfo>,
    broadcast_channel_sender: mpsc::Sender<(String, Vec<u8>)>,
}

struct Blockchain {
    chain: VecDeque<Vec<u8>>,
    registry: HashSet<String>,
    broadcast_channel_receiver: mpsc::Receiver<(String, Vec<u8>)>,
}

impl Blockchain {
    pub fn new(channel_receiver: mpsc::Receiver<(String, Vec<u8>)>) -> Self {
        return Self {
            chain: VecDeque::new(),
            registry: HashSet::new(),
            broadcast_channel_receiver: channel_receiver,
        };
    }
    pub async fn start_and_run(&mut self, config: P2PConfig) {
        loop {
            tokio::select! {
                incoming_block = self.broadcast_channel_receiver.recv() => {
                    match incoming_block {
                        Some(data) => {
                            let (id, msg) = data;
                            if !(self.registry.contains(&id)){
                                println!("Id of the msg {}",id);
                                self.registry.insert(id);
                                self.chain.push_back(msg.clone());
                                println!("New message added to the chain. Current length: {}", self.chain.len());

                                let streams = connect_to_all_local(config.clone());
                                forward_message_to_peers(msg.as_slice(), streams);
                            }
                        },
                        None => {
                            todo!();
                        },
                    }

            }
            }
        }
    }
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

fn forward_message_to_peers(msg: &[u8], streams: Vec<TcpStream>) {
    for mut stream in streams {
        let _write_all = stream.write_all(msg);
    }

    println!(
        "[BlockchainStubServer] Received forward_share request and send it to the other thetacrypt nodes!"
    );

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
        
        forward_message_to_peers(msg, streams);

        Ok(Response::new(ForwardShareResponse {}))
    }

    async fn atomic_broadcast(
        &self,
        request: Request<AtomicBroadcastRequest>,
    ) -> Result<Response<AtomicBroadcastResponse>, Status> {
        // extracting the message from the response
        let binding = request.into_inner();
        let msg = binding.data.as_slice();
        let id = binding.id;

        //Adding the msg into to the queue (TODO: implement the solution with a second channel and a dedicated function for deliver the TOB msg)
        if let Err(e) = self.broadcast_channel_sender.send((id, msg.to_vec())).await {
            println!("Error occurred during send(): {}", e);
        }
        Ok((Response::new(AtomicBroadcastResponse {})))
    }
}

impl ThetacryptBlockchainStub {

}

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

    println!(
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
            println!("Error {}", e);
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

    let (channel_sender, channel_receiver) = tokio::sync::mpsc::channel::<(String, Vec<u8>)>(100);
    let mut blockchain = Blockchain::new(channel_receiver);

    let service = ThetacryptBlockchainStub {
        peers: config.peers.clone(), //We now here pass the peers coming from the config file. TODO: remove the hard coded ones.
        broadcast_channel_sender: channel_sender,
    };

    //We need a separate process to handle the Blockchain
    tokio::spawn(async move {
        println!("Blockchain is starting");
        blockchain.start_and_run(config.clone()).await
    });

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
