use mcore::hash256::HASH256;
use network::types::message::P2pMessage;
use crate::keychain::KeyChain;
use crate::pb;
use crate::pb::requests::threshold_crypto_library_server::{ThresholdCryptoLibrary,ThresholdCryptoLibraryServer};
use crate::pb::requests::{ThresholdDecryptionRequest, ThresholdDecryptionResponse, self, PushDecryptionShareRequest, PushDecryptionShareResponse};
use cosmos_crypto::dl_schemes::dl_groups::dl_group::DlGroup;
use cosmos_crypto::interface::{ThresholdCipherParams, Ciphertext, Serializable};
use cosmos_crypto::rand::{RNG, RngAlgorithm};
use rand::prelude::SliceRandom;
use rand::thread_rng;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::oneshot;
use tonic::{transport::Server, Request, Response, Status};
use std::sync::mpsc::Receiver;  
use std::{collections::HashSet, thread, sync::mpsc};
use cosmos_crypto::{dl_schemes::{ciphers::{sg02::{Sg02PublicKey, Sg02PrivateKey, Sg02ThresholdCipher, Sg02Ciphertext}, bz03::{Bz03ThresholdCipher, Bz03PrivateKey, Bz03PublicKey, Bz03Ciphertext}}, dl_groups::bls12381::Bls12381}, interface::{ThresholdCipher, PublicKey, PrivateKey, Share}};
use crate::threshold_cipher_protocol::{ThresholdCipherProtocol, Protocol};
use std::collections::{self, HashMap, VecDeque};
use serde::{Serialize, Deserialize};


type InstanceId = String;

const BACKLOG_MAX_RETRIES: u32 = 10;
const BACKLOG_WAIT_INTERVAL: u32 = 5; //seconds. todo: exponential backoff
const CHECK_TERMINATED_CHANNES_INTERVAL: u32 = 30;

#[derive(Debug)]
pub enum MessageForwarderCommand {
    GetReceiverForNewInstance {
        instance_id: String,
        responder: tokio::sync::oneshot::Sender< tokio::sync::mpsc::Receiver<Vec<u8>> >
    },
    RemoveReceiverForInstance {
        instance_id: String
    }
}

// InstanceStatus describes the currenct state of a protocol instance. 
// The field result has meaning only when terminated == true. 
// The result can be None, e.g. when the ciphertext is invalid.
#[derive(Debug, Clone)]
struct InstanceStatus {
    started: bool,
    terminated: bool,
    result: Option<Vec<u8>>, 
}

#[derive(Debug)]
enum StateUpdateCommand {
    // Initiate the status for a new instance. The caller must make sure the instance does not already exist, otherwise the status will be overwritten.
    AddNewInstance { 
        instance_id: String,
    },
    // Return the current status of a protocol instance
    GetInstanceStatus { 
        instance_id: String,
        responder: tokio::sync::oneshot::Sender< InstanceStatus >
    },
    // Update the status of an instance.
    UpdateInstanceStatus { 
        instance_id: String,
        new_status: InstanceStatus
    },
}

fn assign_decryption_instance_id(ctxt: &impl Ciphertext) -> String {
    let mut ctxt_digest = HASH256::new();
    ctxt_digest.process_array(&ctxt.get_msg());
    let h: &[u8] = &ctxt_digest.hash()[..8];
    String::from_utf8(ctxt.get_label()).unwrap() + " " + hex::encode_upper(h).as_str()
}

pub struct RpcRequestHandler {
    key_chain: KeyChain,
    state_command_sender: tokio::sync::mpsc::Sender<StateUpdateCommand>,
    forwarder_command_sender: tokio::sync::mpsc::Sender<MessageForwarderCommand>,
    outgoing_message_sender: tokio::sync::mpsc::Sender<P2pMessage>,
    result_sender: tokio::sync::mpsc::Sender<(InstanceId, Option<Vec<u8>>)>,
    incoming_message_sender: tokio::sync::mpsc::Sender<P2pMessage>, // needed only for testing, to "patch" messages received over the RPC Endpoint PushDecryptionShare
}

impl RpcRequestHandler{
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
        let ciphertext = match C::CT::deserialize(&req.ciphertext) {
            Ok(ctxt) => ctxt,
            Err(_) =>  {
                println!(">> REQH: ERROR: Failed to deserialize ciphertext in request.");
                return Err(Status::new(tonic::Code::InvalidArgument, "Failed to deserialize ciphertext."))
            }
        };
        let instance_id = assign_decryption_instance_id(&ciphertext);
        
        // Check whether an instance with this instance_id already exists
        let (response_sender, response_receiver) = oneshot::channel::<InstanceStatus>();
        let cmd = StateUpdateCommand::GetInstanceStatus { instance_id: instance_id.clone(), responder: response_sender };
        self.state_command_sender.send(cmd).await.expect("state_command_sender.send() returned Err");
        let response = response_receiver.await.expect("response_receiver.await returned Err");
        if response.started {
             println!(">> REQH: A request with the same id already exists. Instance_id: {:?}", instance_id);
             return Err(Status::new(tonic::Code::AlreadyExists, format!("A similar request with request_id {instance_id} already exists.")))
        }
        
        // Initiate the state of the new instance.
        let cmd = StateUpdateCommand::AddNewInstance { instance_id: instance_id.clone()};
        self.state_command_sender.send(cmd).await.expect("Receiver for state_command_sender closed.");

        // Inform the MessageForwarder that a new instance is starting. The MessageForwarder will return a receiver end that the instnace can use to recieve messages.
        let (response_sender, response_receiver) = oneshot::channel::<tokio::sync::mpsc::Receiver::<Vec<u8>>>();
        let cmd = MessageForwarderCommand::GetReceiverForNewInstance { instance_id: instance_id.clone(), responder: response_sender };
        self.forwarder_command_sender.send(cmd).await.expect("Receiver for forwarder_command_sender closed.");
        let receiver_for_new_instance = response_receiver.await.expect("The sender for response_receiver dropped before sending a response.");

        // Start the new protocol instance as a new tokio task
        let mut prot = ThresholdCipherProtocol::<C>::new(
            sk.clone(),
            pk.clone(),
            ciphertext,
            receiver_for_new_instance,
            self.outgoing_message_sender.clone(),
            self.result_sender.clone(),
            instance_id.clone()
        );

        // println!(">> REQH: Spawning new protocol instance with instance_id: {:?}", &instance_id);
        tokio::spawn( async move {
            prot.run().await; 
        });

        Ok(Response::new(requests::ThresholdDecryptionResponse { instance_id }))
    }
}

#[tonic::async_trait]
impl ThresholdCryptoLibrary for RpcRequestHandler {
    
    async fn decrypt(&self, request: Request<ThresholdDecryptionRequest>) -> Result<Response<ThresholdDecryptionResponse>, Status> {
        let req = request.get_ref();
        println!(">> REQH: Received a decryption request. Decrypting with key_id: {:?}", req.key_id);
        
        let req_scheme = requests::ThresholdCipher::from_i32(req.algorithm).unwrap();
        let req_domain = requests::DlGroup::from_i32(req.dl_group).unwrap();
        let key = self.key_chain.get_key(req_scheme, req_domain, None);
        if let Err(err) = key {
            return Err(Status::new(tonic::Code::InvalidArgument, "Key"))
        }
        let serialized_key = key.unwrap();

        // todo: The reason we retrieve the pk here (and not inside the protocol instance) is because of the ThresholdCipher::TPrivKey vs PrivateKey::TPrivKey compiler error.
        match (req_scheme, req_domain) {
            (requests::ThresholdCipher::Sg02, requests::DlGroup::Bls12381)  => {
                let sk = Sg02PrivateKey::<Bls12381>::deserialize(&serialized_key).unwrap();
                let pk = sk.get_public_key();                
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
        // println!(">> NET: Received a decryption share. Instance_id: {:?}. Pushing to net_to_demult channel,", req.instance_id);
        let p2p_message = P2pMessage{
            instance_id: req.instance_id.clone(),
            message_data: req.decryption_share.clone()
        };
        self.incoming_message_sender.send(p2p_message).await.unwrap();
        Ok(Response::new(requests::PushDecryptionShareResponse{}))
    }
}


pub async fn init(rpc_listen_address: String,
                  rpc_listen_port: u32,
                  key_chain: KeyChain,
                  mut incoming_message_receiver: tokio::sync::mpsc::Receiver<P2pMessage>,
                  outgoing_message_sender: tokio::sync::mpsc::Sender<P2pMessage>,
                  incoming_message_sender: tokio::sync::mpsc::Sender<P2pMessage>, // needed only for testing, to "patch" messages received over the RPC Endpoint PushDecryptionShare
                 ) {
    
    // Channel to send commands to the StateManager. There are three places in the code such a command can be sent from:
    // - The RpcRequestHandler, when a new request is received (it takes ownership state_command_sender)
    // - The MessageForwarder, when it wants to know whether an instance has already finished (it takes ownership of state_command_sender2)
    // - The InstanceMonitor, when it updated the StateManger with the result of an instance (it takes ownership of state_command_sender3)
    // The channel must never be closed. In fact, both senders must remain open for ever.
    let (state_command_sender, mut state_command_receiver) = tokio::sync::mpsc::channel::<StateUpdateCommand>(32);
    let state_command_sender2 = state_command_sender.clone();
    let state_command_sender3 = state_command_sender.clone();

    // Channel to send commands to the MessageForwarder. Such a command is only sent when a new protocol instance is started.
    // The sender end is owned by the RpcRequestHandler and must never be closed.
    let (forwarder_command_sender, mut forwarder_command_receiver) = tokio::sync::mpsc::channel::<MessageForwarderCommand>(32);
    let forwarder_command_sender2 = forwarder_command_sender.clone();

    // Channel to communicate the result of each instance back to the RpcRequestHandler.
    // The result_sender is meant to be cloned and given to every instance. 
    // However, the channel must never be closed (i.e., one sender end, owned by the RpcRequestHandler, must always remain open).
    let (result_sender, mut result_receiver) = tokio::sync::mpsc::channel::<(InstanceId, Option<Vec<u8>>)>(32);

    // Spawn State Manager
    println!(">> REQH: Initiating the state manager.");
    tokio::spawn( async move {
        let mut instances_status_map: HashMap<String, InstanceStatus> = HashMap::new();
        loop {
            tokio::select! {
                state_update_command = state_command_receiver.recv() => { // Received a state-update command
                    let command: StateUpdateCommand = state_update_command.expect("All senders for state_command_receiver have been closed.");
                    match command {
                        StateUpdateCommand::AddNewInstance { instance_id} => {
                            let status = InstanceStatus{
                                started: true,
                                terminated: false,
                                result: None,
                            };
                            instances_status_map.insert(instance_id, status);
                        },
                        StateUpdateCommand::GetInstanceStatus { instance_id, responder} => {
                            let result = match instances_status_map.get(&instance_id) {
                                Some(status) => {
                                    (*status).clone()
                                },
                                None => {
                                    InstanceStatus{
                                        started: false,
                                        terminated: false,
                                        result: None,
                                    }
                                },
                            };
                            responder.send(result).expect("The receiver for responder in StateUpdateCommand::GetInstanceResult has been closed.");
                        },
                        StateUpdateCommand::UpdateInstanceStatus { instance_id, new_status } => {
                            instances_status_map.insert(instance_id, new_status);
                        }
                        _ => unimplemented!()
                    }
                }

                // instance_result = result_receiver.recv() => { // A protocol instance has terminated. Update the status of that instance
                //     let (instance_id, result_data) = instance_result.expect("All senders for result_receiver have been dropped.");
                //     println!(">> SMAN: Received result in result_channel. Instance_id: {:?}", instance_id);
                //     let new_status = InstanceStatus{
                //         started: true,
                //         terminated: true,
                //         result: result_data,
                //     };
                //     instances_status_map.insert(instance_id, new_status);
                // }
            }
        }
    });

    // Spawn MessageForwarder
    // Responsible for forwarding messages to the appropriate instance (hence also maintaining a channel with each instance)
    // and backlogging messages when instance has not yet started.
    println!(">> REQH: Initiating MessageForwarder.");
    tokio::spawn( async move {
        let mut instance_senders: HashMap<InstanceId, tokio::sync::mpsc::Sender<Vec<u8>> >= HashMap::new();
        let mut backlogged_messages: VecDeque<(P2pMessage, u32)> = VecDeque::new();
        let mut backlog_interval = tokio::time::interval(tokio::time::Duration::from_secs(BACKLOG_WAIT_INTERVAL as u64));
        let mut check_terminated_interval = tokio::time::interval(tokio::time::Duration::from_secs(CHECK_TERMINATED_CHANNES_INTERVAL as u64));
        loop {
            tokio::select! {
                incoming_message = incoming_message_receiver.recv() => { // An incoming message was received.
                    let P2pMessage{instance_id, message_data} = incoming_message.expect("The channel for incoming_message_receiver has been closed.");
                    if let Some(instance_sender) = instance_senders.get(&instance_id) {
                        instance_sender.send(message_data).await; // No error if this returns Err, it only means the instance has in the meanwhile finished.
                        // println!(">> FORW: Forwarded message in net_to_prot. Instance_id: {:?}", &instance_id);
                    }
                    else { 
                        // No channel was found for the given instance_id. This can happen for two reasons:
                        // - The instance has already finished and the corresponding sender has been removed from the instance_senders.
                        // - The instance has not yet started because the corresponding request has not yet arrived.
                        let (response_sender, response_receiver) = oneshot::channel::<InstanceStatus>();
                        let cmd = StateUpdateCommand::GetInstanceStatus { instance_id: instance_id.clone(), responder: response_sender };
                        state_command_sender2.send(cmd).await.expect("The receiver for state_command_sender3 has been closed.");
                        let status = response_receiver.await.expect("The sender for response_receiver dropped before sending a response.");
                        if ! status.started { // - The instance has not yet started... Backlog the message.
                            println!(">> FORW: Could not forward message to protocol instance. Instance_id: {instance_id} does not exist yet. Will retry after {BACKLOG_WAIT_INTERVAL} seconds. Retries left: {BACKLOG_MAX_RETRIES}.");
                            backlogged_messages.push_back((P2pMessage{instance_id: instance_id.clone(), message_data}, BACKLOG_MAX_RETRIES));
                        }
                        else if status.terminated { // - The instance has already finished... Do nothing
                            // println!(">> FORW: Did not forward message in net_to_prot. Instance already terminated. Instance_id: {:?}", &instance_id);
                        }
                        else { // This should never happen. If status.started and !status.terminated, there should be a channel to that instance.
                            println!(">> FORW: ERROR: Could not find channel to protocol instance. Instance_id: {:?}", &instance_id);
                        }
                    }
                }

                _ = backlog_interval.tick() => { // Retry sending the backlogged messages
                    // let mut instances_seen: HashSet<&InstanceId> = HashSet::new();
                    for _ in 0..backlogged_messages.len() { // always pop_front() and push_back(). If we pop_front() exactly backlogged_messages.len() times, we are ok.
                        let (P2pMessage{instance_id, message_data}, retries_left) = backlogged_messages.pop_front().unwrap(); 
                        if let Some(instance_sender) = instance_senders.get(&instance_id) {
                            instance_sender.send(message_data).await; 
                            println!(">> FORW: Forwared message in net_to_prot. Instance_id: {:?}", &instance_id);
                        }
                        else { // Instance still not started. If there are tries left, push_back() the message again
                            if retries_left > 0 {
                                backlogged_messages.push_back((P2pMessage{instance_id: instance_id.clone(), message_data}, retries_left - 1));
                                println!(">> FORW: Could not forward message to protocol instance. Will retry after {BACKLOG_WAIT_INTERVAL} seconds Retries left: {:?}. Instance_id: {instance_id}", retries_left - 1);
                            }
                            else {
                                println!(">> FORW: Could not forward message to protocol instance. Abandoned after {BACKLOG_MAX_RETRIES} retries. Instance_id: {instance_id}");
                            }
                        }
                    }
                    
                }

                forwarder_command = forwarder_command_receiver.recv() => { // Received a command.
                    let command = forwarder_command.expect("Sender for forwarder_command_receiver closed.");
                    match command {
                        MessageForwarderCommand::GetReceiverForNewInstance { instance_id , responder} => {
                            let (message_to_instance_sender, message_to_instance_receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                            instance_senders.insert(instance_id, message_to_instance_sender);
                            responder.send(message_to_instance_receiver).expect("The receiver for responder in MessageForwarderCommand::GetReceiverForNewInstance has been closed.");
                        },
                        MessageForwarderCommand::RemoveReceiverForInstance { instance_id} => {
                            instance_senders.remove(&instance_id);
                        }
                    }
                }
                
            }
        }
    });
    
    // Spawn Instance Monitor
    println!(">> REQH: Initiating InstanceMonitor.");
    tokio::spawn( async move {
        loop {
            let result = result_receiver.recv().await;
            let (instance_id, result_data) = result.expect("All senders for result_receiver have been dropped.");
            println!(">> INMO: Received result in result_channel. Instance_id: {:?}", instance_id);
            // Update status of terminated instance
            let new_status = InstanceStatus{
                started: true,
                terminated: true,
                result: result_data,
            };
            let cmd = StateUpdateCommand::UpdateInstanceStatus { instance_id: instance_id.clone(), new_status};
            state_command_sender3.send(cmd).await.expect("The receiver for state_command_sender3 has been closed.");
            // Inform MessageForwarder that the instance was terminated
            let cmd = MessageForwarderCommand::RemoveReceiverForInstance { instance_id: instance_id.clone() };
            forwarder_command_sender.send(cmd).await.expect("The receiver for forwarder_command_sender has been closed.")
        }
    });
    
    // Start server
    let rpc_addr = format!("{}:{}", rpc_listen_address, rpc_listen_port);
    println!(">> REQH: Request handler is starting. Listening on address: {rpc_addr}");
    let service = RpcRequestHandler{
        key_chain,
        state_command_sender,
        forwarder_command_sender: forwarder_command_sender2,
        outgoing_message_sender,
        result_sender,
        incoming_message_sender,
    };
    Server::builder()
        .add_service(ThresholdCryptoLibraryServer::new(service))
        // .serve(format!("[{rpc_listen_address}]:{rpc_listen_port}").parse().unwrap())
        .serve(rpc_addr.parse().unwrap())
        .await.expect("");
}