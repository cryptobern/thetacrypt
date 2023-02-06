use cosmos_crypto::proto::scheme_types::{ThresholdScheme, Group};
use mcore::hash256::HASH256;
use prost::Message;
use tokio::sync::mpsc::Sender;
use tonic::Code;
use std::collections::{HashMap, VecDeque};

use tokio::sync::oneshot;
use tonic::{transport::Server, Request, Response, Status};

use network::types::message::P2pMessage;
use cosmos_crypto::keys::{PrivateKey, PublicKey};
use crate::keychain::{KeyChain, PrivateKeyEntry};
use crate::proto::protocol_types::threshold_crypto_library_server::{ThresholdCryptoLibrary,ThresholdCryptoLibraryServer};
use crate::proto::protocol_types::{DecryptRequest, DecryptReponse, DecryptSyncRequest, DecryptSyncReponse, GetDecryptResultRequest, GetDecryptResultResponse};
use crate::proto::protocol_types::{PushDecryptionShareRequest, PushDecryptionShareResponse};
use crate::proto::protocol_types::{GetPublicKeysForEncryptionRequest, GetPublicKeysForEncryptionResponse};
use crate::proto::protocol_types::PublicKeyEntry;
use cosmos_crypto::interface::Ciphertext;
use crate::protocol::ProtocolError;
use crate::threshold_cipher_protocol::ThresholdCipherProtocol;


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
// The field result has meaning only when finished == true. 
#[derive(Debug, Clone)]
struct InstanceStatus {
    started: bool,
    finished: bool,
    result: Result<Vec<u8>, ProtocolError>, 
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
    // Returns the private keys that can be used with the given scheme and group
    GetPrivateKeyByType { 
        scheme: ThresholdScheme,
        group: Group,
        responder: tokio::sync::oneshot::Sender< Result<PrivateKeyEntry, String> >
    },
    // Returns all public keys that can be used for encryption.
    GetPublicKeysForEncryption { 
        responder: tokio::sync::oneshot::Sender< Result<Vec<PublicKeyEntry>, String> >
    },
}

fn assign_decryption_instance_id(ctxt: &Ciphertext) -> String {
    let mut ctxt_digest = HASH256::new();
    ctxt_digest.process_array(&ctxt.get_msg());
    let h: &[u8] = &ctxt_digest.hash()[..8];
    String::from_utf8(ctxt.get_label()).unwrap() + " " + hex::encode_upper(h).as_str()
}

pub struct RpcRequestHandler {
    state_command_sender: tokio::sync::mpsc::Sender<StateUpdateCommand>,
    forwarder_command_sender: tokio::sync::mpsc::Sender<MessageForwarderCommand>,
    outgoing_message_sender: tokio::sync::mpsc::Sender<P2pMessage>,
    incoming_message_sender: tokio::sync::mpsc::Sender<P2pMessage>, // needed only for testing, to "patch" messages received over the RPC Endpoint PushDecryptionShare
}

impl RpcRequestHandler {
    async fn get_decryption_instance(&self, ciphertext_bytes: &Vec<u8>, key_id: &Option<String>) -> Result<(String,ThresholdCipherProtocol), Status> {
        // Deserialize ciphertext
        let ciphertext = match Ciphertext::deserialize(ciphertext_bytes) {
            Ok(ctxt) => ctxt,
            Err(err) => {
                return Err(Status::new(Code::InvalidArgument, format!("Could not deserialize ciphertext. Err: {:?}", err)));
            },
        };
        
        // Create a unique instance_id for this instance
        let instance_id = assign_decryption_instance_id(&ciphertext);
        
        // Check whether an instance with this instance_id already exists
        let (response_sender, response_receiver) = oneshot::channel::<InstanceStatus>();
        let cmd = StateUpdateCommand::GetInstanceStatus { instance_id: instance_id.clone(), responder: response_sender };
        self.state_command_sender.send(cmd).await.expect("Receiver for state_command_sender closed.");
        let status = response_receiver.await.expect("response_receiver.await returned Err");
        if status.started {
             println!(">> REQH: A request with the same id already exists. Instance_id: {:?}", instance_id);
             return Err(Status::new(Code::AlreadyExists, format!("A similar request with request_id {instance_id} already exists.")))
        }
        
        // Retrieve private key for this instance
        let private_key_result: Result<PrivateKeyEntry, String> = if let Some(id) = key_id {
            unimplemented!(">> REQH: Using specific key by specifying its id not yet supported.")
        }
        else {
            let (response_sender, response_receiver) = oneshot::channel::<Result<PrivateKeyEntry, String>>();
            let cmd = StateUpdateCommand::GetPrivateKeyByType { scheme: ciphertext.get_scheme(), group: ciphertext.get_group().clone(), responder: response_sender };
            self.state_command_sender.send(cmd).await.expect("Receiver for state_command_sender closed.");
            let status = response_receiver.await.expect("response_receiver.await returned Err");
            status
        };
        let private_key_entry = match private_key_result{
            Ok(key_entry) => key_entry,
            Err(err) => {
                return Err(Status::new(Code::InvalidArgument, err));
            }
        };
        println!(">> REQH: Using key with id: {:?} for request {:?}", private_key_entry.id, &instance_id);
        let private_key: PrivateKey = private_key_entry.key;
        let public_key: PublicKey = private_key.get_public_key();

        // Initiate the state of the new instance.
        let cmd = StateUpdateCommand::AddNewInstance { instance_id: instance_id.clone()};
        self.state_command_sender.send(cmd).await.expect("Receiver for state_command_sender closed.");

        // Inform the MessageForwarder that a new instance is starting. The MessageForwarder will return a receiver end that the instnace can use to recieve messages.
        let (response_sender, response_receiver) = oneshot::channel::<tokio::sync::mpsc::Receiver::<Vec<u8>>>();
        let cmd = MessageForwarderCommand::GetReceiverForNewInstance { instance_id: instance_id.clone(), responder: response_sender };
        self.forwarder_command_sender.send(cmd).await.expect("Receiver for forwarder_command_sender closed.");
        let receiver_for_new_instance = response_receiver.await.expect("The sender for response_receiver dropped before sending a response.");

        // Create the new protocol instance
        let prot = ThresholdCipherProtocol::new(
            private_key.clone(),
            public_key.clone(),
            ciphertext,
            receiver_for_new_instance,
            self.outgoing_message_sender.clone(),
            instance_id.clone()
        );
        Ok((instance_id, prot))
    }

    async fn update_decryption_instance_result(instance_id: String,
                                               result: Result<Vec<u8>, ProtocolError>, 
                                               state_command_sender: Sender<StateUpdateCommand>,
                                               forwarder_command_sender: Sender<MessageForwarderCommand>) {
        // Update the StateManager with the result of the instance.
        let new_status = InstanceStatus{
            started: true,
            finished: true,
            result,
        }; 
        let cmd = StateUpdateCommand::UpdateInstanceStatus { instance_id: instance_id.clone(), new_status};
        state_command_sender.send(cmd).await.expect("The receiver for state_command_sender has been closed.");
        
        // Inform MessageForwarder that the instance was terminated.
        let cmd = MessageForwarderCommand::RemoveReceiverForInstance { instance_id };
        forwarder_command_sender.send(cmd).await.expect("The receiver for forwarder_command_sender has been closed.");
    }
}

#[tonic::async_trait]
impl ThresholdCryptoLibrary for RpcRequestHandler {
    
    async fn decrypt(&self, request: Request<DecryptRequest>) -> Result<Response<DecryptReponse>, Status> {
        println!(">> REQH: Received a decrypt request.");
        let req: &DecryptRequest = request.get_ref();

        // Make all required checks and create the new protocol instance
        let (instance_id, mut prot) = match self.get_decryption_instance(&req.ciphertext, &req.key_id).await{
            Ok((instance_id, prot)) => (instance_id, prot),
            Err(err) => return Err(err),
        };
    
        // Start it in a new thread, so that the client does not block until the protocol is finished.
        let state_command_sender2 = self.state_command_sender.clone();
        let forwarder_command_sender2 = self.forwarder_command_sender.clone();
        let instance_id2 = instance_id.clone();
        tokio::spawn( async move {
            let result = prot.run().await;
            
            // Protocol terminated, update state with the result.
            println!(">> REQH: Received result from protocol with instance_id: {:?}", instance_id2);
            RpcRequestHandler::update_decryption_instance_result(instance_id2.clone(),
                                                                 result, 
                                                                 state_command_sender2, 
                                                                 forwarder_command_sender2).await;
        });

        Ok(Response::new(DecryptReponse { instance_id: instance_id.clone() }))
    }

    async fn decrypt_sync(&self, request: Request<DecryptSyncRequest>) -> Result<Response<DecryptSyncReponse>, Status> {
        println!(">> REQH: Received a decrypt_sync request.");
        let req: &DecryptSyncRequest = request.get_ref();

        // Do all required checks and create the new protocol instance
        let (instance_id, mut prot) = match self.get_decryption_instance(&req.ciphertext, &req.key_id).await{
            Ok((instance_id, prot)) => (instance_id, prot),
            Err(err) => return Err(err),
        };

        // Start the new protocol instance
        let result = prot.run().await;

        // Protocol terminated, update state with the result.
        println!(">> REQH: Received result from protocol with instance_id: {:?}", instance_id);
        
        RpcRequestHandler::update_decryption_instance_result(instance_id.clone(),
                                                             result.clone(), 
                                                             self.state_command_sender.clone(), 
                                                             self.forwarder_command_sender.clone()).await;

        let return_result = match result {
            Ok(res) => Some(res),
            Err(_) => None
        };
        Ok(Response::new(DecryptSyncReponse { instance_id: instance_id.clone(), plaintext: return_result }))
    }

    async fn get_public_keys_for_encryption(&self, request: Request<GetPublicKeysForEncryptionRequest>) -> Result<Response<GetPublicKeysForEncryptionResponse>, Status> { 
        println!(">> REQH: Received a get_public_keys_for_encryption request.");
        let (response_sender, response_receiver) = oneshot::channel::< Result< Vec<PublicKeyEntry>, String> >();
        let cmd = StateUpdateCommand::GetPublicKeysForEncryption { responder: response_sender } ;
        self.state_command_sender.send(cmd).await.expect("Receiver for state_command_sender closed.");
        let encryption_pks = response_receiver.await.expect("response_receiver.await returned Err");
        match encryption_pks {
            Ok(keys) => {
                // println!(">> REQH: Responding with {:?}.", keys[0].key);
                Ok(Response::new(GetPublicKeysForEncryptionResponse { keys }))
            },
            Err(err) => Err(Status::new(Code::Internal, err)),
        }
    }

    async fn get_decrypt_result(&self, request: Request<GetDecryptResultRequest>) -> Result<Response<GetDecryptResultResponse>, Status> {
        println!(">> REQH: Received a get_decrypt_result request.");
        let req: &GetDecryptResultRequest = request.get_ref();

        // Get status of the instance by contacting the state manager
        let (response_sender, response_receiver) = oneshot::channel::<InstanceStatus>();
        let cmd = StateUpdateCommand::GetInstanceStatus { instance_id: req.instance_id.clone(), responder: response_sender };
        self.state_command_sender.send(cmd).await.expect("Receiver for state_command_sender closed.");
        let status = response_receiver.await.expect("response_receiver.await returned Err");

        let mut result = None;
        if status.finished {
            if let Ok(res) = status.result { 
                result = Some(res) 
            };            
        };
        let response = GetDecryptResultResponse{ instance_id: req.instance_id.clone(),
                                                                           is_started: status.started, 
                                                                           is_finished: status.finished, 
                                                                           plaintext: result };
        Ok(Response::new(response))
    }
    
    // Meant only for testing. In real depolyments decryption shares are sent through a separate libP2P-based network.
    async fn push_decryption_share(&self, request: Request<PushDecryptionShareRequest>) -> Result<Response<PushDecryptionShareResponse>, Status> {
        let req = request.get_ref();
        // println!(">> NET: Received a decryption share. Instance_id: {:?}. Pushing to net_to_demult channel,", req.instance_id);
        let p2p_message = P2pMessage{
            instance_id: req.instance_id.clone(),
            message_data: req.decryption_share.clone()
        };
        self.incoming_message_sender.send(p2p_message).await.unwrap();
        Ok(Response::new(PushDecryptionShareResponse{}))
    }
}


pub async fn init(rpc_listen_address: String,
                  rpc_listen_port: u32,
                  keychain: KeyChain,
                  mut incoming_message_receiver: tokio::sync::mpsc::Receiver<P2pMessage>,
                  outgoing_message_sender: tokio::sync::mpsc::Sender<P2pMessage>,
                  incoming_message_sender: tokio::sync::mpsc::Sender<P2pMessage>, // needed only for testing, to "patch" messages received over the RPC Endpoint PushDecryptionShare
                 ) {
    
    // Channel to send commands to the StateManager. There are two places in the code such a command can be sent from:
    // - The RpcRequestHandler, when a new request is received (it takes ownership state_command_sender)
    // - The MessageForwarder, when it wants to know whether an instance has already finished (it takes ownership of state_command_sender2)
    // The channel must never be closed. In fact, both senders must remain open for ever.
    let (state_command_sender, mut state_command_receiver) = tokio::sync::mpsc::channel::<StateUpdateCommand>(32);
    let state_command_sender2 = state_command_sender.clone();

    // Channel to send commands to the MessageForwarder. Such a command is only sent when a new protocol instance is started.
    // The sender end is owned by the RpcRequestHandler and must never be closed.
    let (forwarder_command_sender, mut forwarder_command_receiver) = tokio::sync::mpsc::channel::<MessageForwarderCommand>(32);
    // let forwarder_command_sender2 = forwarder_command_sender.clone();

    // Channel to communicate the result of each instance back to the RpcRequestHandler.
    // The result_sender is meant to be cloned and given to every instance. 
    // However, the channel must never be closed (i.e., one sender end, owned by the RpcRequestHandler, must always remain open).
    // let (result_sender, mut result_receiver) = tokio::sync::mpsc::channel::<(InstanceId, Option<Vec<u8>>)>(32);

    // Spawn StateManager.
    // Takes ownerhsip of keychain
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
                                finished: false,
                                result: Err(ProtocolError::InstanceNotFound),
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
                                        finished: false,
                                        result: Err(ProtocolError::InstanceNotFound),
                                    }
                                },
                            };
                            responder.send(result).expect("The receiver for responder in StateUpdateCommand::GetInstanceResult has been closed.");
                        },
                        StateUpdateCommand::UpdateInstanceStatus { instance_id, new_status } => {
                            instances_status_map.insert(instance_id, new_status);
                        }
                        StateUpdateCommand::GetPrivateKeyByType { scheme, group, responder } => {
                            let key_entry = keychain.get_key_by_type(scheme, group);
                            responder.send(key_entry).expect("The receiver for responder in StateUpdateCommand::GetPrivateKeyByType has been closed.");
                        },
                        StateUpdateCommand::GetPublicKeysForEncryption { responder } => {
                            let pks = keychain.get_public_keys_for_encryption();
                            responder.send(pks).expect("The receiver for responder in StateUpdateCommand::GetPrivateKeyByType has been closed.");
                        },
                        _ => unimplemented!()
                    }
                }
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
        let check_terminated_interval = tokio::time::interval(tokio::time::Duration::from_secs(CHECK_TERMINATED_CHANNES_INTERVAL as u64));
        loop {
            tokio::select! {
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
                
                incoming_message = incoming_message_receiver.recv() => { // An incoming message was received.
                    let P2pMessage{instance_id, message_data} = incoming_message.expect("The channel for incoming_message_receiver has been closed.");
                    forward_or_backlog(&instance_id, message_data, BACKLOG_MAX_RETRIES, &instance_senders, &mut backlogged_messages, &state_command_sender2).await;
                }

                _ = backlog_interval.tick() => { // Retry sending the backlogged messages
                    for _ in 0..backlogged_messages.len() { // always pop_front() and push_back(). If we pop_front() exactly backlogged_messages.len() times, we are ok.
                        let (P2pMessage{instance_id, message_data}, retries_left) = backlogged_messages.pop_front().unwrap(); 
                        forward_or_backlog(&instance_id, message_data, retries_left, &instance_senders, &mut backlogged_messages, &state_command_sender2).await;
                    }
                    
                }
                
            }
        }
    });
    
    // Start server
    let rpc_addr = format!("{}:{}", rpc_listen_address, rpc_listen_port);
    println!(">> REQH: Request handler is starting. Listening for RPC on address: {rpc_addr}");
    let service = RpcRequestHandler{
        state_command_sender,
        forwarder_command_sender,
        outgoing_message_sender,
        // result_sender,
        incoming_message_sender,
    };
    Server::builder()
        .add_service(ThresholdCryptoLibraryServer::new(service))
        // .serve(format!("[{rpc_listen_address}]:{rpc_listen_port}").parse().unwrap())
        .serve(rpc_addr.parse().unwrap())
        .await.expect("");
}


async fn forward_or_backlog(instance_id: &String, 
                            message_data: Vec<u8>, 
                            backlog_retries_left: u32,
                            instance_senders: &HashMap<InstanceId, tokio::sync::mpsc::Sender<Vec<u8>> >,
                            backlogged_messages: &mut VecDeque<(P2pMessage, u32)>,
                            state_command_sender: &Sender<StateUpdateCommand> ){
    // A channel was found for the given instance_id.
    if let Some(instance_sender) = instance_senders.get(instance_id) {
        instance_sender.send(message_data).await; // No error if this returns Err, it only means the instance has in the meanwhile finished.
        println!(">> FORW: Forwarded message in net_to_prot. Instance_id: {:?}", &instance_id);
    }
    else { 
        // No channel was found for the given instance_id. This can happen for two reasons:
        // - The instance has already finished and the corresponding sender has been removed from the instance_senders.
        // - The instance has not yet started because the corresponding request has not yet arrived.
        // Ask the StateManager to find out what is the case.
        let (response_sender, response_receiver) = oneshot::channel::<InstanceStatus>();
        let cmd = StateUpdateCommand::GetInstanceStatus { instance_id: instance_id.clone(), responder: response_sender };
        state_command_sender.send(cmd).await.expect("The receiver for state_command_sender3 has been closed.");
        let status = response_receiver.await.expect("The sender for response_receiver dropped before sending a response.");
        if ! status.started { 
        // The instance has not yet started. Backlog the message, except if it was already backlogged too many times.
            if backlog_retries_left > 0 {
                backlogged_messages.push_back((P2pMessage{instance_id: instance_id.clone(), message_data}, backlog_retries_left - 1));
                println!(">> FORW: Could not forward message to instance. Instance_id: {instance_id} does not exist yet. Retrying after {BACKLOG_WAIT_INTERVAL} seconds. Retries left: {backlog_retries_left}.");
            }
            else {
                println!(">> FORW: Could not forward message to protocol instance. Abandoned after {BACKLOG_MAX_RETRIES} retries. Instance_id: {instance_id}");
            }
        }
        else if status.finished { 
        // The instance has already finished. Do not backlog the message.
            // println!(">> FORW: Did not forward message in net_to_prot. Instance already terminated. Instance_id: {:?}", &instance_id);
        }
        else { 
        // This should never happen. If status.started and !status.terminated, there should be a channel to that instance.
            println!(">> FORW: INTERNAL ERROR: Could not find channel to instance. Instance_id: {:?}", &instance_id);
        }
    }
}