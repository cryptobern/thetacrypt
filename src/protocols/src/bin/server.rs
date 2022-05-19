use protocols::keychain::KeyChain;
use protocols::requests::threshold_crypto_library_server::{ThresholdCryptoLibrary,ThresholdCryptoLibraryServer};
use protocols::requests::{ThresholdDecryptionRequest, ThresholdDecryptionResponse, self, PushDecryptionShareRequest, PushDecryptionShareResponse};
use cosmos_crypto::dl_schemes::dl_groups::dl_group::DlGroup;
use cosmos_crypto::interface::{ThresholdCipherParams, Ciphertext, Serializable};
use cosmos_crypto::rand::{RNG, RngAlgorithm};
use rand::prelude::SliceRandom;
use rand::thread_rng;
use rasn::der::decode;
use tokio::sync::mpsc::error::TryRecvError;
use tonic::{transport::Server, Request, Response, Status};
use std::convert::TryInto;
use std::fs::{File, self};
use std::str::from_utf8;
use std::{collections::HashSet, thread, sync::mpsc};
use cosmos_crypto::{dl_schemes::{ciphers::{sg02::{Sg02PublicKey, Sg02PrivateKey, Sg02ThresholdCipher, Sg02Ciphertext}, bz03::{Bz03ThresholdCipher, Bz03PrivateKey, Bz03PublicKey, Bz03Ciphertext}}, dl_groups::bls12381::Bls12381}, interface::{ThresholdCipher, PublicKey, PrivateKey, Share}};
use protocols::threshold_cipher_protocol::{ThresholdCipherProtocol, Protocol};
use std::collections::{self, HashMap};
use serde::{Serialize, Deserialize};

enum StateUpdateCommand {
    AddNetToProtChannel {
        instance_id: String,
        sender: tokio::sync::mpsc::Sender<Vec<u8>>
    },
    AddProtToNetChannel {
        instance_id: String,
        receiver: tokio::sync::mpsc::Receiver<Vec<u8>>
    },
    ForwardMessageToProt {
        instance_id: String,
        message: Vec<u8>,
    }
}

pub struct Context {
    key_chain: KeyChain,
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
called state_manager_sender. All updates to the state (i.e., adding and removing network-to-protocol and protocol-to-network
channels) take place by sending a StateUpdateCommand on state_manager_sender.
2) When the Request Handler receives a share it uses the State Manager to forward it to the intended protocol instance
through the appropriate network-to-protocol channel. Shares are received asynchronously, hence we do not give the Request
Handler direct access to the network-to-protocol channels. Instead, the Request Hadler sends the share to the State Manager
as a StateUpdateCommand and the State Manager sends it over the appropriate channel.
3) It loops over all protocol-to-network channels and forwards the messages to the Network.

Key management:
Right now keys are read from file "keys_<replica_id>" upon initialization (in the tokio::main function).
There is one key for every possible combination of algorithm and domain. In the future, the user should
be able to ask our library to create more keys.
Each key is uniquely identified by a key-id and contains the secret key (through which we have access
to the corresponding public key and the threshold) and the key metadata (for now, the algorithm and domain
it can be used for).
When a request is received, we use the key that corresponds to the algorithm and DlGroup fields of the request.
todo: Redesign this. The user should not have to specify all of the algorithm, domain, and key. Probably only key?

Context:
Context variable that contains all the variables required by the Reuest Handler and the protocols.
There must exist only one instance of Context.

TODOs:
- There are many clone() calls, see if you can avoid them (especially in the request handler methods that are executed often, eg cloning keys).
- There are many unwrap(). Handle failures.
*/

// #[derive(Debug, Default)]
pub struct RequestHandler {
    context: Context,
    state_manager_sender: tokio::sync::mpsc::Sender<StateUpdateCommand>, 
    // ctxt_sg02: Sg02Ciphertext<Bls12381>,
    // ctxt_bz03: Bz03Ciphertext<Bls12381>,
}

impl RequestHandler{
    async fn start_decryption_instance<C: ThresholdCipher>(&self, 
                                                           req: ThresholdDecryptionRequest,
                                                           sk: C::TPrivKey,
                                                           pk: C::TPubKey) 
                                                        -> Result<Response<ThresholdDecryptionResponse>, Status>
        where <C as cosmos_crypto::interface::ThresholdCipher>::TPrivKey: Send,
            <C as cosmos_crypto::interface::ThresholdCipher>::TPubKey: Send,
            <C as cosmos_crypto::interface::ThresholdCipher>::TShare: Send,
            <C as cosmos_crypto::interface::ThresholdCipher>::CT: Send,
            C: 'static
    {
        let ciphertext = C::CT::deserialize(&req.ciphertext).unwrap(); 
                
        // let sk = decode::<Sg02PrivateKey<Bls12381>>(&self.context.key_chain.get("sg02_bls12381").unwrap().sk).unwrap();
        // todo: remove rasn dependency if you keep this version
        
        // Identify each protocol instance with a unique id. This id will be used to forward decryption shares to the
        // corresponding protocol instance. Right now we use the label of the ciphertext as id/
        let instance_id = String::from_utf8(ciphertext.get_label()).unwrap();

        // Create a channel for network-to-protocol communication and one for protocol-to-network communication.
        let (net_to_prot_tx, net_to_prot_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let (prot_to_net_tx, prot_to_net_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        
        // Update the state. We need to keep the sender end of net_to_prot channel and the receiver end of prot_to_net. The state manager takes ownership.
        let cmd = StateUpdateCommand::AddNetToProtChannel { instance_id: instance_id.clone(), sender: net_to_prot_tx };
        let _ = self.state_manager_sender.send(cmd).await;
        let cmd = StateUpdateCommand::AddProtToNetChannel { instance_id: instance_id.clone(), receiver: prot_to_net_rx };
        let _ = self.state_manager_sender.send(cmd).await;

        // The receiver end of net_to_prot channel and the sender end of prot_to_net are given to the protocol. The protocol takes ownership.
        let mut prot = ThresholdCipherProtocol::<C>::new(
            sk.clone(),
            pk.clone(),
            ciphertext,
            net_to_prot_rx,
            prot_to_net_tx,
            instance_id.clone());
        
        // Start the new protocol instance as a new tokio task
        println!("Spawning new protocol instance with instance_id: {:?}", &instance_id);
        tokio::spawn( async move {
            prot.run(); // Which primitive values are Send? Arc? Does it make sense to use or does it introduce locks/race connditions?
        });

        Ok(Response::new(requests::ThresholdDecryptionResponse { instance_id }))
    }
}

#[tonic::async_trait]
impl ThresholdCryptoLibrary for RequestHandler {
    
    async fn decrypt(&self, request: Request<ThresholdDecryptionRequest>) -> Result<Response<ThresholdDecryptionResponse>, Status> {
        let req = request.get_ref();
        println!("Received a decryption request. Key_id: {:?}", req.key_id);
        
        let req_scheme = requests::ThresholdCipher::from_i32(req.algorithm).unwrap();
        let req_domain = requests::DlGroup::from_i32(req.dl_group).unwrap();
        let key = self.context.key_chain.get_key(req_scheme, req_domain, None);
        if let Err(err) = key {
            return Err(Status::new(tonic::Code::InvalidArgument, "Key"))
        }
        let serialized_key = key.unwrap();

        // todo: implement these enums in cosmos_crypto library, not in proto
        match (req_scheme, req_domain) {
            (requests::ThresholdCipher::Sg02, requests::DlGroup::Bls12381)  => {
                let sk = Sg02PrivateKey::<Bls12381>::deserialize(&serialized_key).unwrap();
                let pk = sk.get_public_key();
                // todo: The reason we retrieve the pk here (and not inside the protocol instance) is because of the ThresholdCipher::TPrivKey vs PrivateKey::TPrivKey compiler error.
                self.start_decryption_instance::<Sg02ThresholdCipher<Bls12381>>(req.clone(), sk, pk).await
            },
            (requests::ThresholdCipher::Bz02, requests::DlGroup::Bls12381) => {
                let sk = Bz03PrivateKey::<Bls12381>::deserialize(&serialized_key).unwrap();
                let pk = sk.get_public_key();
                self.start_decryption_instance::<Bz03ThresholdCipher<Bls12381>>(req.clone(), sk, pk).await
            },
            (_, _) => {
                Err(Status::new(tonic::Code::InvalidArgument, "Requested scheme and domain.s"))
            }
        }
    }

    async fn push_decryption_share(&self, request: Request<PushDecryptionShareRequest>) -> Result<Response<PushDecryptionShareResponse>, Status> {
        let req = request.get_ref();
        println!("Received a decryption share. Instance_id: {:?}", req.instance_id);
        let cmd = StateUpdateCommand::ForwardMessageToProt { instance_id: req.instance_id.clone(), message: req.decryption_share.clone() };
        let _ = self.state_manager_sender.send(cmd).await;
        let response = requests::PushDecryptionShareResponse{};
        Ok(Response::new(response))
    }

    
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Spawn the State Manager
    let (state_manager_sender, mut state_manager_receiver) = tokio::sync::mpsc::channel::<StateUpdateCommand>(32);
    tokio::spawn(async move {
        let mut channels_net_to_prot: HashMap<String, tokio::sync::mpsc::Sender<Vec<u8>> > = HashMap::new();
        let mut channels_prot_to_net: HashMap<String, tokio::sync::mpsc::Receiver<Vec<u8>> > = HashMap::new();
        loop {
            // Handle incoming commands (i.e., requests to modify the state).
            match state_manager_receiver.try_recv() { 
                Ok(cmd) => {`
                    match cmd {
                        StateUpdateCommand::AddNetToProtChannel { instance_id, sender } => {
                            channels_net_to_prot.insert(instance_id, sender); // todo: right now sender will be updated if instance_id already exists
                        },
                        StateUpdateCommand::AddProtToNetChannel { instance_id, receiver } => {
                            channels_prot_to_net.insert(instance_id, receiver); // todo: right now receiver will be updated if instance_id already exists
                        },
                        StateUpdateCommand::ForwardMessageToProt { instance_id, message } => {
                            println!("State manager forwarding decryption share in net_to_prot. Instance_id: {:?}", instance_id);
                            if channels_net_to_prot.contains_key(&instance_id) { // todo: Handle case where channel does not exist
                                let sender = channels_net_to_prot.get(&instance_id).unwrap();
                                sender.send(message).await.unwrap(); //todo: This should be spawned in a separate task, so that the task manager does not stall
                            }
                        },
                    }
                },
                Err(TryRecvError::Disconnected) => {}, // sender end closed
                Err(_) => {}
            };
            // Handle messages from protocol instances (by sending them through the network)
            // todo: Move into a separate module?
            for (instance_id, receiver) in channels_prot_to_net.iter_mut(){
                match receiver.try_recv() {
                    Ok(message) => {
                        println!("State manager received decryption share in prot_to_net. Instance_id: {:?}", instance_id);
                        // todo: Broadcast this message to everyone using Tendermint Core.
                    },
                    Err(TryRecvError::Disconnected) => {}, // sender end closed
                    Err(_) => {}
                };
            }
            
        }
    });
    
    // Read keys from file
    println!("Reading keys from keychain.");
    let keyfile = format!("keys_0.json");
    let key_chain_str = fs::read_to_string(keyfile).unwrap();
    let key_chain: KeyChain = serde_json::from_str(&key_chain_str).unwrap();
    println!("Reading keys done");
    
    // Setup the request handler
    let context = Context {
        key_chain
    };

    // Start
    let addr = "[::1]:50051".parse()?;
    let service = RequestHandler{
        context,
        state_manager_sender,
    };
    
    Server::builder()
        .add_service(ThresholdCryptoLibraryServer::new(service))
        .serve(addr)
        .await?;
    Ok(())
}