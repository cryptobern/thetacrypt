use std::time::Duration;

use tonic::transport::Channel;

use crate::proto::protocol_types::{threshold_crypto_library_client::ThresholdCryptoLibraryClient, self};

type PeerId = u32;
type IpAddres = String;
type Port = u32;
type InstanceId = String;

pub struct RpcNetwork{
    peers: Vec<(PeerId, IpAddres, Port)>,
    connections: Vec<ThresholdCryptoLibraryClient<Channel>>,
    my_id: PeerId,
    pub net_to_demult_sender: tokio::sync::mpsc::Sender<(InstanceId, Vec<u8>)>,
    pub prot_to_net_receiver: tokio::sync::mpsc::Receiver<(InstanceId, Vec<u8>)>,
}

impl RpcNetwork{
    pub async fn new(my_id: PeerId,
                     net_to_demult_sender: tokio::sync::mpsc::Sender<(InstanceId, Vec<u8>)>,
                     prot_to_net_receiver: tokio::sync::mpsc::Receiver<(InstanceId, Vec<u8>)>,) -> Self
    {
        let peers = vec![
                (0, String::from("localhost"), 50050),
                (1, String::from("::1"), 50050),
                (2, String::from("::1"), 50050),
                (3, String::from("::1"), 50050)
        ];
        
        let mut handles = Vec::new();
        for peer in peers.iter() {
            let (id, ip, port) = peer.clone();
            if id == my_id {
                continue;
            }
            handles.push(tokio::spawn(async move {
                loop {
                    let addr = format!("http://[{ip}]:{port}");
                    match ThresholdCryptoLibraryClient::connect(addr.clone()).await{
                        Ok(client) => {
                            println!(">> NET: Connected to peer with id: {:?}", id);    
                            return client;
                        }
                        Err(e) => {
                            println!(">> NET: Could not connect to peer with id: {id} with address: {addr}. Retrying in 2 sec. {e}" );   
                            tokio::time::sleep(Duration::from_millis(2000)).await;
                        },
                    }
                }
            }));
        }
        
        let mut connections = Vec::new();
        for handle in handles {
            connections.push(handle.await.expect(">> NET: Failed to connect to peers."));
        }
        println!(">> NET: Connected to all peers");    
        RpcNetwork{peers, connections, my_id, net_to_demult_sender, prot_to_net_receiver }
    }

    // pub fn send(&self, instance_id: String, message: Vec<u8>){

    // }

    pub async fn send_to_all(&mut self, instance_id: String, message: Vec<u8>){
        for connection in self.connections.iter_mut(){
            let req = requests::PushDecryptionShareRequest{
                instance_id :instance_id.clone(),
                decryption_share: message.clone(),
            };
            let response = connection.push_decryption_share(req).await;
            // println!("RESPONSE={:?}", response);
        }
    }
}