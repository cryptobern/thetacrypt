use prost::Message;
use protocols::requests::threshold_protocol_server::{ThresholdProtocol,ThresholdProtocolServer};
use protocols::requests::{ThresholdDecryptionRequest, ThresholdDecryptionResponse, self};
use cosmos_crypto::dl_schemes::dl_groups::dl_group::DlGroup;
use cosmos_crypto::interface::{ThresholdCipherParams, Ciphertext, Serializable};
use cosmos_crypto::rand::{RNG, RngAlgorithm};
use rand::prelude::SliceRandom;
use rand::thread_rng;
use tokio::sync::mpsc::error::TryRecvError;
use tonic::{transport::Server, Request, Response, Status};
use std::convert::TryInto;
use std::{collections::HashSet, thread, sync::mpsc};
use cosmos_crypto::{dl_schemes::{ciphers::{sg02::{Sg02PublicKey, Sg02PrivateKey, Sg02ThresholdCipher, Sg02Ciphertext}, bz03::{Bz03ThresholdCipher, Bz03PrivateKey, Bz03PublicKey, Bz03Ciphertext}}, dl_groups::bls12381::Bls12381}, interface::{ThresholdCipher, PublicKey, PrivateKey, Share}};
use protocols::threshold_cipher_protocol::ThresholdCipherProtocol;
use std::collections::{self, HashMap};


enum StateUpdateCommand {
    AddNetToProtChannel {
        instance_id: Vec<u8>,
        sender: tokio::sync::mpsc::Sender<Vec<u8>>
    },
    AddProtToNetChannel {
        instance_id: Vec<u8>,
        receiver: tokio::sync::mpsc::Receiver<Vec<u8>>
    },
    ForwardMessageToProt {
        instance_id: Vec<u8>,
        message: Vec<u8>,
    }
}

pub struct Context {
    pub threshold: usize,
    pub pk_sg02_bls12381: Sg02PublicKey<Bls12381>,
    pub sk_sg02_bls12381: Sg02PrivateKey<Bls12381>,
    pub pk_bz03_bls12381: Bz03PublicKey<Bls12381>,
    pub sk_bz03_bls12381: Bz03PrivateKey<Bls12381>,
}

/*
Request Handler:
The idea is that there exists a single request handler struct (the ThresholdProtocolService),
and the corresponding handler method is run every time a request is received.
It checks the exact type of the request and starts the appropriate protocol as a new tokio task.
Each protocol (tokio task) owns: 
1) chan_in: the receiver end of a network-to-protocol channel, used for receiving messages (such as shares) from the network, and
2) chan_out: the sender end of a protocol-to-network channel, used for sending messages to the network.
These channels are created by the handler just before spawning the new tokio task.

State Manager:
There exists a seperate tokio task, the StateManager, responsible for the folloqing:
1) Handling the state of the request handler,
i.e., the sender ends of the network-to-protocol channels and the receiver ends of protocol-to-network channels.
The StateManager is created once, in the tokio::main function. It exposes a sender channel end to the request handler,
called state_manager_tx. All updates to the state (i.e., adding and removing network-to-protocol and protocol-to-network
channels) take place by sending a StateUpdateCommand on state_manager_tx.
2) When the Request Handler receives a share it uses the State Manager to forward it to the intended protocol instance
through the appropriate network-to-protocol channel. Shares are received asynchronously, hence we do not give the Request
Handler direct access to the network-to-protocol channels. Instead, the Request Hadler sends the share to the State Manager
as a StateUpdateCommand and the State Manager sends it over the appropriate channel.
3) It loops over all protocol-to-network channels and forwards the messages to the Network.
*/

// #[derive(Debug, Default)]
pub struct ThresholdProtocolService {
    context: Context,
    state_manager_tx: tokio::sync::mpsc::Sender<StateUpdateCommand>, 
    // ctxt_sg02: Sg02Ciphertext<Bls12381>,
    // ctxt_bz03: Bz03Ciphertext<Bls12381>,
}

#[tonic::async_trait]
impl ThresholdProtocol for ThresholdProtocolService {
    async fn decrypt(&self, request: Request<ThresholdDecryptionRequest>) -> Result<Response<ThresholdDecryptionResponse>, Status> {
        println!("Got a request: {:?}", request);
        let decryption_request = request.get_ref();
        // if self.existing_seq_numbers.contains(&decryption_request.sn.try_into().unwrap()) {
        //     return Err(Status::already_exists(format!("A decryption request with the given sn {} already exists.", decryption_request.sn)));
        // };
        // self.existing_seq_numbers.insert(decryption_request.sn.try_into().unwrap());
      
        // todo: See how you can simplify the code by extracting the declaration of prot here:
        // let mut prot: ThresholdCipherProtocol<_>; 
        match (requests::ThresholdCipher::from_i32(decryption_request.algorithm).unwrap(), requests::DlGroup::from_i32(decryption_request.dl_group).unwrap()) {
            (requests::ThresholdCipher::Sg02, requests::DlGroup::Bls12381)  => {
                let ciphertext = Sg02Ciphertext::deserialize(decryption_request.ciphertext.clone()).unwrap(); 

                // Create a channel for network-to-protocol communication and one for protocol-to-network communication.
                let (net_to_prot_tx, net_to_prot_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                let (prot_to_net_tx, prot_to_net_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                
                // Update the state. We need to keep the sender end of net_to_prot channel and the receiver end of prot_to_net. The state manager takes ownership.
                let cmd = StateUpdateCommand::AddNetToProtChannel { instance_id: ciphertext.get_label() , sender:net_to_prot_tx };
                let c = self.state_manager_tx.send(cmd).await;
                let cmd = StateUpdateCommand::AddProtToNetChannel { instance_id: ciphertext.get_label() , receiver:prot_to_net_rx };
                let c = self.state_manager_tx.send(cmd).await;

                // The receiver end of net_to_prot channel and the sender end of prot_to_net are given to the protocol. The protocol takes ownership.
                let mut prot = ThresholdCipherProtocol::<Sg02ThresholdCipher<Bls12381>>::new(
                    self.context.threshold, 
                    self.context.pk_sg02_bls12381.clone(), 
                    self.context.sk_sg02_bls12381.clone(), 
                    ciphertext,
                    net_to_prot_rx,
                    prot_to_net_tx);
              
                // Start the new protocol instance as a new tokio task
                tokio::spawn( async move {
                    prot.run();
                });
            },
            (requests::ThresholdCipher::Bz02, requests::DlGroup::Bls12381) => {
                // let ciphertext = Bz03Ciphertext::deserialize(decryption_request.ciphertext).unwrap(); 
                // let mut prot = ThresholdCipherProtocol::<Bz03ThresholdCipher<Bls12381>>::new(
                //     self.context.threshold, 
                //     self.context.pk_bz03_bls12381.clone(), 
                //     self.context.sk_bz03_bls12381.clone(), 
                //     ciphertext,);
                // thread::spawn( move || {
                //     prot.run();
                // });
            },
        };
        let reply = requests::ThresholdDecryptionResponse {
            // label: format!("Received request {}.", decryption_request.get_label()).encode_to_vec(),
            label: format!("Received request ").encode_to_vec(),
        };

        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Spawn the State Manager
    let (state_manager_tx, mut state_manager_rx) = tokio::sync::mpsc::channel::<StateUpdateCommand>(32);
    tokio::spawn(async move {
        let mut channels_net_to_prot: HashMap<Vec<u8>, tokio::sync::mpsc::Sender<Vec<u8>> > = HashMap::new();
        let mut channels_prot_to_net: HashMap<Vec<u8>, tokio::sync::mpsc::Receiver<Vec<u8>> > = HashMap::new();
        loop {
            // Handle incoming commands (i.e., requests to modify the state).
            match state_manager_rx.try_recv() { 
                Ok(cmd) => {
                    match cmd {
                        StateUpdateCommand::AddNetToProtChannel { instance_id, sender } => {
                            channels_net_to_prot.insert(instance_id, sender); // todo: right now sender will be updated if instance_id already exists
                        },
                        StateUpdateCommand::AddProtToNetChannel { instance_id, receiver } => {
                            channels_prot_to_net.insert(instance_id, receiver); // todo: right now receiver will be updated if instance_id already exists
                        },
                        StateUpdateCommand::ForwardMessageToProt { instance_id, message } => {
                            if channels_net_to_prot.contains_key(&instance_id) { // todo: Handle case where channel does not exist
                                let sender = channels_net_to_prot.get(&instance_id).unwrap();
                                sender.send(message);
                            }
                        },
                    }
                },
                Err(TryRecvError::Disconnected) => {}, // sender end closed
                Err(_) => {}
            };
            // Handle messages from protocol instances (by sending them through the network)
            // todo: Move into a separate module?
            for (instance, receiver) in channels_prot_to_net.iter_mut(){
                match receiver.try_recv() {
                    Ok(message) => {
                        // Broadcast this message to everyone.
                    },
                    Err(TryRecvError::Disconnected) => {}, // sender end closed
                    Err(_) => {}
                };
            }
            
        }
    });
    

    // Setup the request handler
    // todo: Remove code, read keys, id, IP address from config files, once you can (de)serialize
    const k: usize = 3; // threshold
    const n: usize = 4; // total number of secret shares
    let id = 0;
    let mut rng = RNG::new(RngAlgorithm::MarsagliaZaman);
    let sk_sg02_bls12381 = Sg02ThresholdCipher::generate_keys(k, n, Bls12381::new(), &mut rng);
    let sk_bz03_bls12381 = Bz03ThresholdCipher::generate_keys(k, n, Bls12381::new(), &mut rng);
    
    let context = Context {
        threshold: k,
        pk_sg02_bls12381: sk_sg02_bls12381[id].get_public_key(),
        sk_sg02_bls12381: sk_sg02_bls12381[id].clone(),
        pk_bz03_bls12381: sk_bz03_bls12381[id].get_public_key(),
        sk_bz03_bls12381: sk_bz03_bls12381[id].clone(),
    };

    let addr = "[::1]:50051".parse()?;
    let service = ThresholdProtocolService{
        context,
        state_manager_tx,
    };

    Server::builder()
        .add_service(ThresholdProtocolServer::new(service))
        .serve(addr)
        .await?;
    Ok(())
}