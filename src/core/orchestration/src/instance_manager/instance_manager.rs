use std::{collections::HashMap, sync::Arc, time, thread};

use mcore::hash256::HASH256;
use theta_network::types::message::NetMessage;
use theta_proto::{protocol_types::{SignRequest, DecryptRequest, CoinRequest}, scheme_types::{ThresholdScheme, Group}};
use theta_protocols::{threshold_cipher::protocol::ThresholdCipherProtocol, interface::{ProtocolError, ThresholdProtocol}};
use theta_schemes::interface::{Ciphertext, Serializable, ThresholdCryptoError};
use tokio::sync::oneshot;
use tonic::{Status, Code};

use crate::{state_manager::{ StateManagerCommand, StateManagerMsg, StateManagerResponse }, message_dispatcher::MessageDispatcherCommand, types::Key};
use crate::instance_manager::instance::Instance;

pub struct InstanceManager {
    state_command_sender: tokio::sync::mpsc::Sender<StateManagerMsg>,
    instance_command_receiver: tokio::sync::mpsc::Receiver<InstanceManagerCommand>,
    instance_command_sender: tokio::sync::mpsc::Sender<InstanceManagerCommand>,
    outgoing_p2p_sender: tokio::sync::mpsc::Sender<NetMessage>,
    incoming_p2p_receiver: tokio::sync::mpsc::Receiver<NetMessage>,
    instances:HashMap<String, Instance>,
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
                println!(">> Got no response from state manager");
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
            instances: HashMap::new()
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
                                None => println!("Error storing instance result for instance {}", instance_id)
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
                    return Err(ThresholdCryptoError::Aborted);
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
            _ => {
                return Ok(String::from(""));
            }
        }
    }

    fn start_protocol(mut prot: (impl ThresholdProtocol + std::marker::Send + 'static), 
    instance_id: String, 
    sender: tokio::sync::mpsc::Sender<InstanceManagerCommand>) {
        tokio::spawn(async move {
            let result = prot.run().await;

            // Protocol terminated, update state with the result.
            println!(
                ">> REQH: Received result from protocol with instance_id: {:?}",
                instance_id
            );

            while sender.send(InstanceManagerCommand::StoreResult { 
                instance_id: instance_id.clone(),
                result:result.clone()
            }).await.is_err() {
                // loop until transmission successful
                println!(">> Error storing result, retrying...");
                thread::sleep(time::Duration::from_millis(500)); // wait for 500ms before trying again
            }
        });
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
            println!(
                ">> REQH: A request with the same id already exists. Instance_id: {:?}",
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
            unimplemented!(">> REQH: Using specific key by specifying its id not yet supported.")
        } else {

            let key_result = 
                call_state_manager!(self, StateManagerCommand::GetPrivateKeyByType {
                    scheme,
                    group:group.clone(),
            },
            StateManagerResponse::Key);

            if(key_result.is_none()) {
                println!(">> Got no response from state manager");
                return Err(Status::aborted("Could not get a response from state manager"));
            } 

            match key_result.unwrap() {
                Ok(key_entry) => key = key_entry,
                Err(err) => return Err(Status::new(Code::InvalidArgument, err)),
            };
        };
        println!(
            ">> REQH: Using key with id: {:?} for request {:?}",
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
            message might become a bottleneck for big messages */
            digest.process_array(&name); 
            let h: &[u8] = &digest.hash()[..8];
            return hex::encode(h);
        }
    }
}