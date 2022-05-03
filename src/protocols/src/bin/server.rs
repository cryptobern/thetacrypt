use prost::Message;
use protocols::requests::threshold_protocol_server::{ThresholdProtocol,ThresholdProtocolServer};
use protocols::requests::{ThresholdDecryptionRequest, ThresholdDecryptionResponse, self};
use cosmos_crypto::dl_schemes::dl_groups::dl_group::DlGroup;
use cosmos_crypto::interface::{ThresholdCipherParams, Ciphertext, Serializable};
use cosmos_crypto::rand::{RNG, RngAlgorithm};
use rand::prelude::SliceRandom;
use rand::thread_rng;
use tonic::{transport::Server, Request, Response, Status};
use std::convert::TryInto;
use std::{collections::HashSet, thread, sync::mpsc};
use cosmos_crypto::{dl_schemes::{ciphers::{sg02::{Sg02PublicKey, Sg02PrivateKey, Sg02ThresholdCipher, Sg02Ciphertext}, bz03::{Bz03ThresholdCipher, Bz03PrivateKey, Bz03PublicKey, Bz03Ciphertext}}, dl_groups::bls12381::Bls12381}, interface::{ThresholdCipher, PublicKey, PrivateKey, Share}};
use protocols::threshold_cipher_protocol::ThresholdCipherProtocol;
use std::collections::{self, HashMap};

// struct MessageMultiplexor {
//     net_to_prot: HashMap<String, tokio::sync::mpsc::Sender<Vec<u8>> >,
//     prot_to_net: tokio::sync::mpsc::Receiver<Vec<u8>>,   
// }

enum Command {
    AddChannel {
        receiver_id: Vec<u8>,
        sender: tokio::sync::mpsc::Sender<Vec<u8>>
    },
    SendMessage {
        receiver_id: Vec<u8>,
        message: Vec<u8>,
    }
}

// #[derive(Debug)]
pub struct Context {
    pub threshold: usize,
    pub pk_sg02_bls12381: Sg02PublicKey<Bls12381>,
    pub sk_sg02_bls12381: Sg02PrivateKey<Bls12381>,
    pub pk_bz03_bls12381: Bz03PublicKey<Bls12381>,
    pub sk_bz03_bls12381: Bz03PrivateKey<Bls12381>,
}

/*
The idea is that there exists a single RequestHandler, and on_receive_decrypt_request() is run every time a request is received.
It checks it's exact type and starts the appropriate protocol in an new thread.
todo: Give the rx of a channel to the thread so we can pass p2p/abc messages directly to the it and the tx of a channel so it can send messages to the p2p/abc layer. (?)
todo: Do not pass the request to the protocol, but only the data it needs (request.threshold and request.ciphertext).
This way the IF of the request will not be tied to the protocol but only to the RequestHandler.*/

// #[derive(Debug, Default)]
pub struct ThresholdProtocolService {
    context: Context,
    // Sender end of the channel shared between ThresholdProtocolService and Message Handler.
    // Used to send updates to the Message Handler.
    message_handler_tx: tokio::sync::mpsc::Sender<Command>, 
    // Sender end of a channel between each protocol instance and the Message Handler.
    // Used to send messages from each protocol instance to the network
    // existing_seq_numbers: HashSet<usize>,
    // // todo: Ciphertexts are here just because we cannot yet deserialize the ones in the request. To be removed.
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
                let ciphertext = Sg02Ciphertext::decode(decryption_request.ciphertext).unwrap(); 

                // Create a channel for network to instance communication and one for instance to network communication.
                let (net_to_prot_tx, net_to_prot_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                let (prot_to_net_tx, prot_to_net_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                
                // Give the sender end of the net_to_prot channel and the receiver end of prot_to_net to the message handler...
                let cmd = Command::AddNetToProtChannel { receiver_id: ciphertext.get_label() , sender:net_to_prot_tx };
                let c = self.message_handler_tx.send(cmd).await;
                let cmd = Command::AddProtToNetChannel { receiver_id: ciphertext.get_label() , receiver:prot_to_net_rx };
                let c = self.message_handler_tx.send(cmd).await;

                // ...and the reciever end to the protocol instance.
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
                let ciphertext = Bz03Ciphertext::decode(decryption_request.ciphertext).unwrap(); 
                let mut prot = ThresholdCipherProtocol::<Bz03ThresholdCipher<Bls12381>>::new(self.context.threshold, self.context.pk_bz03_bls12381.clone(), self.context.sk_bz03_bls12381.clone(), ciphertext);
                thread::spawn( move || {
                    prot.run();
                });
            },
        };
        let reply = requests::ThresholdDecryptionResponse {
            label: format!("Received request {}.", decryption_request.get_label()),
        };

        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Spawn Message Handler
    let (message_handler_tx, message_handler_rx) = tokio::sync::mpsc::channel::<Command>(32);
    tokio::spawn(async move {
        let channels_net_to_prot: HashMap<Vec<u8>, tokio::sync::mpsc::Sender<Vec<u8>> > = HashMap::new();
        let channels_prot_to_net: Vec<(Vec<u8>, tokio::sync::mpsc::Receiver<Vec<u8>)>; // Vector of pairs channel/instance_id
        loop {
            match message_handler_rx.try_recv() { // Check if a command was sent to us, either to add a new net_to_prot channel or to send a message through a net_to_prot channel
                Ok(cmd) => {
                    match cmd {
                        Command::AddChannel { receiver_id, sender } => {
                            net_to_prot.insert(receiver_id, sender); // sender will be update if receiver_id already exists
                        },
                        Command::SendMessage { receiver_id, message } => {
                            if net_to_prot.contains_key(&receiver_id) { // todo: Handle case where channel does not exist
                                let &sender = net_to_prot.get(&receiver_id).unwrap();
                                sender.send(message);
                            }
                        }
                    }
                },
                Err(_) => {}
            };
            //todo: check each channel in channels_prot_to_net
            match prot_to_net_rx.try_recv() { // Check if any of the protocols sent a message on the prot_to_net channel.
                Ok(message) => {
                    // Broadcast this message to everyone.
                },
                Err(_) => {}
            };
        }
    });
    

    // Setup
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
        message_handler_tx,
        // existing_seq_numbers : HashSet::new()
    };

    Server::builder()
        .add_service(ThresholdProtocolServer::new(service))
        .serve(addr)
        .await?;
    Ok(())
}