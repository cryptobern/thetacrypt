use std::time::Duration;

use tonic::transport::Channel;

use crate::pb::requests::{threshold_crypto_library_client::ThresholdCryptoLibraryClient, self};

type PeerId = u32;
type IpAddres = String;
type Port = u32;

pub struct RpcNetwork{
    peers: Vec<(PeerId, IpAddres, Port)>,
    connections: Vec<ThresholdCryptoLibraryClient<Channel>>,
    my_id: PeerId
}

impl RpcNetwork{
    pub async fn new(my_id: PeerId) -> Self {
        let peers = vec![
                (0, String::from("::1"), 50050),
                (1, String::from("::1"), 50051),
                (2, String::from("::1"), 50052),
                (3, String::from("::1"), 50053)
        ];
        
        let mut handles = Vec::new();
        for peer in peers.iter() {
            let (id, ip, port) = peer.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    match ThresholdCryptoLibraryClient::connect(format!("http://[{ip}]:{port}")).await{
                        Ok(client) => {
                            println!(">> NET: Connected to peer with id: {:?}", id);    
                            return client;
                        }
                        Err(_) => {
                            println!(">> NET: Could not connect to peer with id: {:?}. Retrying in 1 sec.", id);   
                            tokio::time::sleep(Duration::from_millis(1000)).await;
                        },
                    }
                }
            }));
        }
        
        let mut connections = Vec::new();
        for handle in handles {
            connections.push(handle.await.expect(">> NET: Failed to connect to peers."));
        }

        RpcNetwork{peers, connections, my_id}
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
            println!("RESPONSE={:?}", response);
        }
    }
}