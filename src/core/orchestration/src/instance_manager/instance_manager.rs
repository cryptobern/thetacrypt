use core::panic;
use std::{collections::HashMap, sync::Arc, time, thread};

use log::{info, error};
use mcore::hash256::HASH256;
use theta_network::types::message::{NetMessage, self};
use theta_proto::{protocol_types::{SignRequest, DecryptRequest, CoinRequest}, scheme_types::{ThresholdScheme, Group}};
use theta_protocols::{threshold_cipher::protocol::ThresholdCipherProtocol, interface::{ProtocolError, ThresholdProtocol}, threshold_signature::protocol::ThresholdSignatureProtocol, threshold_coin::protocol::ThresholdCoinProtocol};
use theta_schemes::interface::{Ciphertext, Serializable, ThresholdCryptoError};
use tokio::sync::oneshot;
use tonic::{Status, Code};

use crate::{state_manager::{ StateManagerCommand, StateManagerMsg, StateManagerResponse }, types::Key};
use crate::instance_manager::instance::Instance;

pub struct InstanceManager {
    state_command_sender: tokio::sync::mpsc::Sender<StateManagerMsg>,
    instance_command_receiver: tokio::sync::mpsc::Receiver<InstanceManagerCommand>,
    instance_command_sender: tokio::sync::mpsc::Sender<InstanceManagerCommand>,
    outgoing_p2p_sender: tokio::sync::mpsc::Sender<NetMessage>,
    incoming_p2p_receiver: tokio::sync::mpsc::Receiver<NetMessage>,
    instances:HashMap<String, Instance>,
    backlog: HashMap<String, BacklogData>,
    backlog_interval: tokio::time::Interval,
}

const BACKLOG_CHECK_INTERVAL: u64 = 600;

// BacklogData keeps all the messages that are destined for a specific instance,
// plus a field checked, which is used to detect too old backlog data.
struct BacklogData {
    messages: Vec<Vec<u8>>,
    checked: bool,
}

#[derive(Debug)]
pub enum StartInstanceRequest { 
    Decryption {
        ciphertext: Ciphertext
    },
    Signature {
        message: Vec<u8>,
        label: Vec<u8>,
        scheme: ThresholdScheme,
        group: Group
    },
    Coin {
        name: Vec<u8>,
        scheme: ThresholdScheme,
        group: Group
    }
}

// InstanceStatus describes the currenct state of a protocol instance. 
// The field result has meaning only when finished == true. 
#[derive(Debug, Clone)]
pub struct InstanceStatus {
    pub scheme: ThresholdScheme,
    pub group: Group,
    pub finished: bool,
    pub result: Option<Result<Vec<u8>, ProtocolError>>, 
}

#[derive(Debug)]
pub enum InstanceManagerCommand {
    CreateInstance {
        request: StartInstanceRequest,
        responder: tokio::sync::oneshot::Sender<Result<String, ThresholdCryptoError>>,
    },

    GetInstanceStatus {
        instance_id: String,
        responder: tokio::sync::oneshot::Sender<Option<InstanceStatus>>,
    },

    StoreResult {
        instance_id: String,
        result: Result<Vec<u8>, ProtocolError>
    },

    UpdateInstanceStatus {
        instance_id: String,
        status: String
    }
}

#[macro_export]
macro_rules! call_state_manager {
    ( $self:ident, $cmd:expr, $rtype:path ) => {
        {
            let _tmp = $self.call_state_manager($cmd).await;

            if _tmp.is_none()  {
                info!("Got no response from state manager");
                return Err(Status::aborted("Could not get a response from state manager"));
            } 

            if let Option::Some($rtype(s)) = _tmp {
                Option::Some(s)
            } else {
                Option::None
            }
        }
    };
}

impl InstanceManager {
    pub fn new(
        state_command_sender: tokio::sync::mpsc::Sender<StateManagerMsg>,
        instance_command_receiver: tokio::sync::mpsc::Receiver<InstanceManagerCommand>,
        instance_command_sender: tokio::sync::mpsc::Sender<InstanceManagerCommand>,
        outgoing_p2p_sender: tokio::sync::mpsc::Sender<NetMessage>,
        incoming_p2p_receiver: tokio::sync::mpsc::Receiver<NetMessage>) -> Self {
    
        return Self { 
            state_command_sender, 
            instance_command_receiver,
            instance_command_sender,
            outgoing_p2p_sender, 
            incoming_p2p_receiver, 
            instances: HashMap::new(),
            backlog: HashMap::new(),
            backlog_interval: tokio::time::interval(tokio::time::Duration::from_secs(
                BACKLOG_CHECK_INTERVAL as u64,
            ))
        };
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                command = self.instance_command_receiver.recv() => {
                    let cmd = command.expect("");
                    match cmd {
                       InstanceManagerCommand::CreateInstance{
                            request,
                            responder
                        } => {
                            let result = self.start(request).await;
                            responder.send(result).expect("The receiver for responder in StateUpdateCommand::GetInstanceResult has been closed.");
                        },

                        InstanceManagerCommand::GetInstanceStatus { instance_id, responder } => {
                            let result = match self.instances.get(&instance_id) {
                                Some(instance) => {

                                    Some(InstanceStatus {
                                        scheme: instance.get_scheme().clone(),
                                        group: instance.get_group().clone(),
                                        finished: instance.is_finished(),
                                        result: instance.get_result().clone()
                                    })
                                },
                                None => {
                                    None
                                },
                            };

                            responder.send(result).expect("The receiver for responder in StateUpdateCommand::GetInstanceResult has been closed.");
                        },

                        InstanceManagerCommand::StoreResult {instance_id, result } => {
                            let instance = self.instances.get_mut(&instance_id);

                            match instance {
                                Some(_instance) => _instance.set_result(result),
                                None => info!("Error storing instance result for instance {}", instance_id)
                            }
                        },

                        InstanceManagerCommand::UpdateInstanceStatus {instance_id, status } => {
                            let instance = self.instances.get_mut(&instance_id);
                            match instance {
                                Some(_instance) => _instance.set_status(&status),
                                None => {}
                            }
                        }
                    }
                }

                incoming_message = self.incoming_p2p_receiver.recv() => {
                    let NetMessage { 
                        instance_id, 
                        is_total_order, 
                        message_data
                    } = incoming_message.expect("The channel for incoming_message_receiver has been closed.");

                    let instance =  self.instances.get(&instance_id);

                    // First check, if an instance already exists for that message
                    match instance {
                        Some(_instance) => {
                            // If yes, forward the message to the instance. (ok if the following returns Err, it only means the instance has finished in the mean time)
                            _instance.send_message(message_data).await;
                        },
                        None => {
                            // Otherwise, backlog the message. This can happen for two reasons:
                            // - The instance has already finished and the corresponding sender has been removed from the instance_senders.
                            // - The instance has not yet started because the corresponding request has not yet arrived.
                            // In both cases, we backlog the message. If the instance has already been finished,
                            // the backlog will be deleted after at most 2*BACKLOG_CHECK_INTERVAL seconds
                            info!(
                                "Backlogging message for instance with id: {:?}",
                                &instance_id
                            );
                            if let Some(backlog_data) =  self.backlog.get_mut(&instance_id) {
                                backlog_data.messages.push(message_data);
                            } else {
                                let mut backlog_data = BacklogData{ messages: Vec::new(), checked: false };
                                backlog_data.messages.push(message_data);
                                self.backlog.insert(instance_id, backlog_data);
                            }
                        }
                    }
                }

                // Detect and delete too old backlog data, so the backlogged_instances field does not grow forever.
                // We assume that an instance will be started at most BACKLOG_CHECK_INTERVAL seconds
                // after a message for that instance has been received. Otherwise, it will never start, so we can delete backlogged messages.
                // Every BACKLOG_CHECK_INTERVAL seconds, go through all backlogged_instances.
                // If the field 'checked' is true, delete the backlogged instance. If it is false, set it to true.
                // This ensures that, if a backlogged instance gets deleted, then it has been waiting for at least BACKLOG_CHECK_INTERVAL seconds.
                _ = self.backlog_interval.tick() => {
                    self.backlog.retain(|_, v| v.checked == false);
                    for (_, v) in self.backlog.iter_mut(){
                        v.checked = true;
                    }
                    info!("Old backlogged instances deleted");
                }
            }
        }
    }

    pub async fn start<'a>(&mut self, instance_request: StartInstanceRequest) -> Result<String, ThresholdCryptoError> {
        // Create a unique instance_id for this instance
        let instance_id =  assign_instance_id(&instance_request);

        match instance_request {
            StartInstanceRequest::Decryption{
                ciphertext
            } => {

                let key = self.setup_instance(
                    ciphertext.get_scheme(),
                    ciphertext.get_group(),
                    &instance_id,
                Option::None).await;

                if key.is_err() {
                    return Err(ThresholdCryptoError::Aborted(String::from("key not found")));
                }

                let key = Arc::new(key.unwrap().sk.clone());

                let (sender, receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

                let instance = Instance::new(instance_id.clone(),
                                        ciphertext.get_scheme(),
                                    ciphertext.get_group().clone(),
                                    sender);

                // Create the new protocol instance
                let mut prot = ThresholdCipherProtocol::new(
                    key,
                    ciphertext,
                    receiver,
                    self.outgoing_p2p_sender.clone(),
                    instance_id.clone(),
                );

                self.instances.insert(instance_id.clone(), instance);

                
                // Start it in a new thread, so that the client does not block until the protocol is finished.
                Self::start_protocol(prot, instance_id.clone(), self.instance_command_sender.clone());

                return Ok(instance_id.clone());
            },
            StartInstanceRequest::Signature{
                message,
                label,
                scheme,
                group
            } => {

                let key = self.setup_instance(
                    scheme,
                    &group,
                    &instance_id,
                Option::None).await;

                if key.is_err() {
                    return Err(ThresholdCryptoError::Aborted(key.as_ref().unwrap_err().to_string()));
                }

                let key = Arc::new(key.unwrap().sk.clone());

                let (sender, receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

                let instance = Instance::new(instance_id.clone(),
                                        scheme,
                                    group.clone(),
                                    sender);

                // Create the new protocol instance
                let mut prot = ThresholdSignatureProtocol::new(
                    key,
                    Some(&message),
                    &label,
                    receiver,
                    self.outgoing_p2p_sender.clone(),
                    instance_id.clone()
                );

                self.instances.insert(instance_id.clone(), instance);

                
                // Start it in a new thread, so that the client does not block until the protocol is finished.
                Self::start_protocol(prot, instance_id.clone(), self.instance_command_sender.clone());

                return Ok(instance_id.clone());
            },
            StartInstanceRequest::Coin{
                name,
                scheme,
                group
            } => {

                let key = self.setup_instance(
                    scheme,
                    &group,
                    &instance_id,
                Option::None).await;

                if key.is_err() {
                    return Err(ThresholdCryptoError::Aborted(key.as_ref().unwrap_err().message().to_string()));
                }

                let key = Arc::new(key.unwrap().sk.clone());

                let (sender, receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

                let instance = Instance::new(instance_id.clone(),
                                        scheme,
                                        group,
                                    sender);

                // Create the new protocol instance
                let mut prot = ThresholdCoinProtocol::new(
                    key,
                    &name,
                    receiver,
                    self.outgoing_p2p_sender.clone(),
                    instance_id.clone(),
                );

                self.instances.insert(instance_id.clone(), instance);

                
                // Start it in a new thread, so that the client does not block until the protocol is finished.
                Self::start_protocol(prot, instance_id.clone(), self.instance_command_sender.clone());

                return Ok(instance_id.clone());
            }
        }
    }

    fn start_protocol(mut prot: (impl ThresholdProtocol + std::marker::Send + 'static), 
        instance_id: String, 
        sender: tokio::sync::mpsc::Sender<InstanceManagerCommand>) {
        tokio::spawn(async move {
            let result = prot.run().await;

            // Protocol terminated, update state with the result.
            info!(
                "Instance {:?} finished",
                instance_id
            );

            while sender.send(InstanceManagerCommand::StoreResult { 
                instance_id: instance_id.clone(),
                result:result.clone()
            }).await.is_err() {
                // loop until transmission successful
                error!("Error storing result, retrying...");
                thread::sleep(time::Duration::from_millis(500)); // wait for 500ms before trying again
            }
        });
    }

    async fn forward_backlogged_messages(&mut self, instance_id: String) {
        let instance = self.instances.get(&instance_id);

        if instance.is_none() {
            return;
        }
        let instance = instance.unwrap();
    
        let backlog = self.backlog.get(&instance_id);
        if backlog.is_none() {
            return;
        }

        let backlog = backlog.unwrap();
        for msg in &backlog.messages {
            instance.send_message(msg.clone()).await;
        }

        self.backlog.remove(&instance_id);
    }

    async fn call_state_manager(&self, command: StateManagerCommand) -> Option<StateManagerResponse> {
        let (response_sender, response_receiver) = oneshot::channel::<StateManagerResponse>();
        
        let msg = if command.will_respond() {
            StateManagerMsg {
                command,
                responder:Option::Some(response_sender)
            }
        }   else  {
            StateManagerMsg {
                command,
                responder:Option::None
            }
        };

        let wait_for_response = msg.responder.is_some();
        
        if self.state_command_sender
            .send(msg)
            .await.is_err() {
            return None;
        }

        if wait_for_response {
            let response = response_receiver.await;
            if response.is_ok() {
                return Some(response.unwrap());
            }
        }

        None
    }

    async fn setup_instance<'a>(
        &self,
        scheme: ThresholdScheme,
        group: &Group,
        instance_id: &str,
        key_id: Option<String>

    ) -> Result<Arc<Key>, Status> {

        if self.instances.contains_key(instance_id) {
            error!(
                "A request with the same id '{:?}' already exists.",
                instance_id
            );
            return Err(Status::new(
                Code::AlreadyExists,
                format!("A similar request with request_id {instance_id} already exists."),
            ));
        }

        // Retrieve private key for this instance
        let key: Arc<Key>;
        if let Some(_) = key_id {
            unimplemented!("Using specific key by specifying its id not yet supported.");
        } else {

            let key_result = 
                call_state_manager!(self, StateManagerCommand::GetPrivateKeyByType {
                    scheme,
                    group:group.clone(),
            },
            StateManagerResponse::Key);

            if(key_result.is_none()) {
                error!("Got no response from state manager");
                return Err(Status::aborted("Could not get a response from state manager"));
            } 

            match key_result.unwrap() {
                Ok(key_entry) => key = key_entry,
                Err(err) => return Err(Status::new(Code::InvalidArgument, err)),
            };
        };
        info!(
            "Using key with id: {:?} for request {:?}",
            key.id, &instance_id
        );

        Ok(key)
    }
}


/* TODO: rethink how to assign instance ids */
fn assign_instance_id(request: &StartInstanceRequest) -> String {
    let mut digest = HASH256::new();

    match request {
        StartInstanceRequest::Decryption{
            ciphertext
        } => {
            digest.process_array(ciphertext.get_ck()); 
            let h: &[u8] = &digest.hash()[..8];
            return hex::encode(h);
        },
        StartInstanceRequest::Signature{
            message,
            label,
            scheme,
            group
        } => {
            /* PROBLEM: Hashing the whole 
            message might become a bottleneck for big messages */
            digest.process_array(&message); 
            let h: &[u8] = &digest.hash()[..8];
            return hex::encode(h);
        },
        StartInstanceRequest::Coin{
            name,
            scheme,
            group
        }=> {
             /* PROBLEM: Hashing the whole 
            name might become a bottleneck for long names */
            digest.process_array(&name); 
            let h: &[u8] = &digest.hash()[..8];
            return hex::encode(h);
        }
    }
}