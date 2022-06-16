use protocols::keychain::KeyChain;
use protocols::requests::threshold_crypto_library_server::{ThresholdCryptoLibrary,ThresholdCryptoLibraryServer};
use protocols::requests::{ThresholdDecryptionRequest, ThresholdDecryptionResponse, self, PushDecryptionShareRequest, PushDecryptionShareResponse};
use cosmos_crypto::dl_schemes::dl_groups::dl_group::DlGroup;
use cosmos_crypto::interface::{ThresholdCipherParams, Ciphertext, Serializable};
use cosmos_crypto::rand::{RNG, RngAlgorithm};
use rand::prelude::SliceRandom;
use rand::thread_rng;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::oneshot;
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
    GetNetToProtSender {
        instance_id: String,
        responder: tokio::sync::oneshot::Sender<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>
    },
    AddResultChannel {
        instance_id: String,
        receiver: tokio::sync::mpsc::Receiver<Option<Vec<u8>>>
    },
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

The State Manager is spawned in a dedicated os thread, not on a Tokio "green" thread, for the following reason:
Currently, the best way I have found to make the State manager loop over the state_manager_receiver and all the
prot_to_net channels is by having a loop() and try_receive() inside (maybe this is possible with tokio::select!,
but don't know how). But this means the State Manager will be running a busy loop forever (there is no .await).
If we run this as a Tokio task, it will be constantly running, causing other Tokio tasks to starve.

todo: Set tokio::runtime to use default - 1 worker threads, since we are using 1 for the state manager.
https://docs.rs/tokio/1.2.0/tokio/attr.main.html
https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html#examples-2

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
}

impl RequestHandler{
    async fn start_decryption_instance<C: ThresholdCipher>(&self, 
                                                           req: ThresholdDecryptionRequest,
                                                           sk: C::TPrivKey,
                                                           pk: C::TPubKey) 
                                                        -> Result<Response<ThresholdDecryptionResponse>, Status>
        where <C as cosmos_crypto::interface::ThresholdCipher>::TPrivKey: Send + 'static,
            <C as cosmos_crypto::interface::ThresholdCipher>::TPubKey: Send + 'static,
            <C as cosmos_crypto::interface::ThresholdCipher>::TShare: Send + 'static + Sync,
            <C as cosmos_crypto::interface::ThresholdCipher>::CT: Send + 'static,
            C: 'static
    {
        let ciphertext = C::CT::deserialize(&req.ciphertext).unwrap(); 
        
        // Identify each protocol instance with a unique id. This id will be used to forward decryption shares to the
        // corresponding protocol instance. Right now we use the label of the ciphertext as id/
        let instance_id = String::from_utf8(ciphertext.get_label()).unwrap();

        // Create a channel for network-to-protocol communication and one for protocol-to-network communication.
        let (net_to_prot_sender, net_to_prot_receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let (prot_to_net_sender, prot_to_net_receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let (result_sender, result_receiver) = tokio::sync::mpsc::channel::<Option<Vec<u8>>>(32);
        
        // Update the state. We need to keep the sender end of net_to_prot channel and the receiver end of prot_to_net. The state manager takes ownership.
        let cmd = StateUpdateCommand::AddNetToProtChannel { instance_id: instance_id.clone(), sender: net_to_prot_sender };
        let _ = self.state_manager_sender.send(cmd).await;
        let cmd = StateUpdateCommand::AddProtToNetChannel { instance_id: instance_id.clone(), receiver: prot_to_net_receiver };
        let _ = self.state_manager_sender.send(cmd).await;
        let cmd = StateUpdateCommand::AddResultChannel { instance_id: instance_id.clone(), receiver: result_receiver };
        let _ = self.state_manager_sender.send(cmd).await;
        
        // The receiver end of net_to_prot channel and the sender end of prot_to_net are given to the protocol. The protocol takes ownership.
        let mut prot = ThresholdCipherProtocol::<C>::new(
            sk.clone(),
            pk.clone(),
            ciphertext,
            net_to_prot_receiver,
            prot_to_net_sender,
            result_sender,
            instance_id.clone());
        
        // Start the new protocol instance as a new tokio task
        println!(">> RH: Spawning new protocol instance with instance_id: {:?}", &instance_id);
        tokio::spawn( async move {
            prot.run().await; 
        });

        Ok(Response::new(requests::ThresholdDecryptionResponse { instance_id }))
    }
}

#[tonic::async_trait]
impl ThresholdCryptoLibrary for RequestHandler {
    
    async fn decrypt(&self, request: Request<ThresholdDecryptionRequest>) -> Result<Response<ThresholdDecryptionResponse>, Status> {
        let req = request.get_ref();
        println!(">> RH: Received a decryption request. Key_id: {:?}", req.key_id);
        
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
                Err(Status::new(tonic::Code::InvalidArgument, "Requested scheme and domain."))
            }
        }
    }

    async fn push_decryption_share(&self, request: Request<PushDecryptionShareRequest>) -> Result<Response<PushDecryptionShareResponse>, Status> {
        let req = request.get_ref();
        println!(">> RH: Received a decryption share. Instance_id: {:?}", req.instance_id);
        let (responder_tx, responder_rx) = oneshot::channel::<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>();
        // Retrieve the sender (channel ens) that sends to the protocol instance with instance_id.
        // The State Manager will search for the that sender and will hand it back to as through the responder_tx-responder_rx channel.
        // If no such sender exists, the State Manager will send a None value.
        let cmd = StateUpdateCommand::GetNetToProtSender { instance_id: req.instance_id.clone(), responder: responder_tx};
        self.state_manager_sender.send(cmd).await;
        match responder_rx.await{
            Ok(v) => {
                match v {
                    Some(sender) => {
                        println!(">> RH: Pushing decryption share in net_to_prot. Instance_id: {:?}", req.instance_id.clone());
                        if let Err(_) = sender.send(req.decryption_share.clone()).await{
                            // receiver end has already been closed
                            println!(">> RH: Pushing decryption share FAILED. Maybe thread already finished? Instance_id: {:?}", req.instance_id.clone());
                        }
                        Ok(Response::new(requests::PushDecryptionShareResponse{}))
                    },
                    None => {
                        // todo: Handle this:
                        // instance_id might not exist because the instance has already finished -> That's ok.
                        println!(">> RH: Could not push decryption share in net_to_prot. Protocol already finished. Instance_id: {:?}", req.instance_id.clone());
                        Ok(Response::new(requests::PushDecryptionShareResponse{}))
                        // instance_id might not exist because the decryption request has not arrived yet -> Backlog these messages.
                        // Err(Status::new(tonic::Code::NotFound, "instance_id not found"))
                    },
                }
                // let sender2 = sender.clone();
            }
            Err(_) => { // responder_tx was dropped
                Err(Status::new(tonic::Code::Internal, "responder_tx was dropped"))
            },
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Spawn the State Manager
    let (state_manager_sender, mut state_manager_receiver) = tokio::sync::mpsc::channel::<StateUpdateCommand>(32);
    // todo: The following runs a busy loop. For this reason we spawn it to a new thread (and not a tokio task).
    // Not a good solution, because the thread will always be looping, even if no new message arrives. 
    thread::spawn( move || {
        let mut channels_net_to_prot: HashMap<String, tokio::sync::mpsc::Sender<Vec<u8>> > = HashMap::new();
        let mut channels_prot_to_net: HashMap<String, tokio::sync::mpsc::Receiver<Vec<u8>> > = HashMap::new();
        // todo: Do we really need a different channel for every protocol instance?
        let mut result_channels: HashMap<String, tokio::sync::mpsc::Receiver<Option<Vec<u8>>> > = HashMap::new();
        let mut results: HashMap<String, Option<Vec<u8>> > = HashMap::new();
        loop {
            // Handle incoming commands (i.e., requests to modify or read the state).
            match state_manager_receiver.try_recv() { 
                Ok(cmd) => {
                    match cmd {
                        StateUpdateCommand::AddNetToProtChannel { instance_id, sender } => {
                            channels_net_to_prot.insert(instance_id, sender); // todo: right now sender will be updated if instance_id already exists
                        },
                        StateUpdateCommand::AddProtToNetChannel { instance_id, receiver } => {
                            channels_prot_to_net.insert(instance_id, receiver); // todo: right now receiver will be updated if instance_id already exists
                        },
                        StateUpdateCommand::GetNetToProtSender { instance_id, responder } => {
                            // if there is channel sender for that instance_id send it back throught the responder. Otherwise send a None.
                            match channels_net_to_prot.get(&instance_id) {
                                Some(sender) => {
                                    if let Err(_) = responder.send(Some(sender.clone())){
                                        println!("The receiver dropped. Instance_id: {:?}", instance_id);    
                                    }
                                },
                                None => {
                                    responder.send(None);
                                }
                            }
                        },
                        StateUpdateCommand::AddResultChannel { instance_id, receiver } => {
                            result_channels.insert(instance_id.clone(), receiver); // todo: right now receiver will be updated if instance_id already exists
                            results.insert(instance_id.clone(), None);
                        },
                    }
                },
                Err(Empty) => {} //it's ok, just no new message
                Err(TryRecvError::Disconnected) => {}, // sender end closed
            };
            // Handle messages from protocol instances (send them through the network)
            // todo: Move into a separate module? Network Manager?
            for (instance_id, receiver) in channels_prot_to_net.iter_mut(){
                match receiver.try_recv() {
                    Ok(message) => {
                        println!(">> SM: Received decryption share in prot_to_net. Instance_id: {:?}", instance_id);
                        // todo: Broadcast this message to everyone using Tendermint Core.
                    },
                    Err(Empty) => {}
                    Err(TryRecvError::Disconnected) => {}, // sender end dropped
                };
            }
            // Handle results (i.e., return values) from terminated protocol instances.
            // Since the instances are terminated, close all related channel (1 - 3) ends and remove them from state 
            let mut instances_to_remove: Vec<String> = Vec::new();
            for (instance_id, receiver) in result_channels.iter_mut(){
                match receiver.try_recv() {
                    Ok(message) => {
                        println!(">> SM: Received result in result_channel. Instance_id: {:?}", instance_id);
                        results.insert(instance_id.clone(), message);
                        // 1. Remove sender from channels_net_to_prot
                        channels_net_to_prot.remove(instance_id);
                        println!(">> SM: Removed channel from channels_net_to_prot. Instance_id: {:?}", instance_id);
                        // 2. Close and remove receiver from channels_prot_to_net. Also check for outstanding messages in the channel and handle them.
                        match channels_prot_to_net.get_mut(instance_id){
                            Some(receiver) => {
                                receiver.close();
                                println!(">> SM: Closed receiver end from channels_prot_to_net. Instance_id: {:?}", instance_id);
                                // todo: code inside this while loop is duplicate. Can we avoid this
                                while let Some(message) = receiver.blocking_recv() {
                                    println!(">> SM: Received decryption share in prot_to_net. Instance_id: {:?}", instance_id);
                                    // todo: Broadcast this message to everyone using Tendermint Core.
                                };
                                channels_prot_to_net.remove(instance_id);
                                println!(">> SM: Removed channel from channels_prot_to_net. Instance_id: {:?}", instance_id);
                            },
                            None => {
                                println!(">> SM: Warning: Channel already removed from channels_prot_to_net. Instance_id: {:?}", instance_id);
                            },
                        }
                        // 3. Close and remove receiver from result_channels.
                        instances_to_remove.push(instance_id.clone());
                    },    
                    Err(Empty) => {} //it's ok, just no new message
                    Err(TryRecvError::Disconnected) => {}, // sender end closed
                };
            }
            for instance_id in instances_to_remove{
                result_channels.remove(&instance_id);
                println!(">> SM: Removed channel from result_channels. Instance_id: {:?}", instance_id);
            }
        }
    });
    
    // Read keys from file
    println!("Reading keys from keychain.");
    let key_chain: KeyChain = KeyChain::from_file("conf/keys_0.json"); 
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