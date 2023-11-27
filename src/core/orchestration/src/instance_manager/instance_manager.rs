use core::panic;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    thread, time,
};

use log::{debug, error, info};
use mcore::hash256::HASH256;
use theta_events::event::Event;
use theta_network::types::message::NetMessage;
use theta_proto::scheme_types::{Group, ThresholdScheme};
use theta_protocols::{
    interface::{ProtocolError, ThresholdProtocol},
    threshold_cipher::protocol::ThresholdCipherProtocol,
    threshold_coin::protocol::ThresholdCoinProtocol,
    threshold_signature::protocol::ThresholdSignatureProtocol,
};
use theta_schemes::interface::{Ciphertext, ThresholdCryptoError};
use tokio::sync::oneshot;
use tonic::{Code, Status};

use crate::{
    instance_manager::instance::Instance,
    state_manager::{StateManagerCommand, StateManagerMsg, StateManagerResponse},
    types::Key,
};

/// Upper bound on the number of finished instances which to store.
const DEFAULT_INSTANCE_CACHE_SIZE: usize = 100_000;
/// Number of instances which to look at when trying to find ones to eject.
const INSTANCE_CACHE_CLEANUP_SCAN_LENGTH: usize = 10;

/// InstanceCache implements a first-in-first-out store for instances.
///
/// It is configured with an upper bound on the number of finished instances it will store. If a
/// new instance is added while at capacity, the oldest terminated instance is ejected.
///
/// Due to only evicting stored instances, there is no actual upper bound on its size. There could
/// well be an unbounded number of running instances.
struct InstanceCache {
    instance_data: HashMap<String, Instance>,
    capacity: usize,
    terminated_instances: VecDeque<String>,
}

impl InstanceCache {
    fn new(capacity: Option<usize>) -> InstanceCache {
        InstanceCache {
            instance_data: HashMap::new(),
            capacity: capacity.unwrap_or(DEFAULT_INSTANCE_CACHE_SIZE),
            terminated_instances: VecDeque::new(),
        }
    }

    fn get(&self, instance_id: &String) -> Option<&Instance> {
        self.instance_data.get(instance_id)
    }

    fn get_mut(&mut self, instance_id: &String) -> Option<&mut Instance> {
        self.instance_data.get_mut(instance_id)
    }

    fn insert(&mut self, instance_id: String, instance: Instance) {
        if self.instance_data.len() >= self.capacity {
            self.attempt_eject();
        }

        self.instance_data.insert(instance_id, instance);
    }

    /// Inform the instance cache that an instance has terminated, and is elligible for eviction if
    /// space is required.
    fn inform_of_termination(&mut self, instance_id: String) {
        if self.instance_data.contains_key(&instance_id) {
            self.terminated_instances.push_back(instance_id);
        } else {
            error!(
                "Got informed that instance ID {} terminated, but no such instance was found",
                instance_id
            );
        }
    }

    /// Attempts to remove terminated instances from the store to get back to the desired capacity.
    /// Returns the number of ejected instances.
    fn attempt_eject(&mut self) -> usize {
        let mut current_iteration = 0;
        let max_iterations = {
            if self.terminated_instances.len() < INSTANCE_CACHE_CLEANUP_SCAN_LENGTH {
                self.terminated_instances.len()
            } else {
                INSTANCE_CACHE_CLEANUP_SCAN_LENGTH
            }
        };

        debug!(
            "Cleaning up instance store by ejecting up to {} terminated instances.",
            max_iterations
        );

        while current_iteration < max_iterations && self.instance_data.len() > self.capacity {
            let candidate_id = self.terminated_instances.pop_front().unwrap();
            debug!("Ejecting terminated instance {}", candidate_id);
            self.instance_data.remove(&candidate_id);

            current_iteration += 1;
        }

        debug!(
            "Ejected {} instance(s) from instance store. Size (current / target): {} / {}",
            current_iteration,
            self.instance_data.len(),
            self.capacity
        );

        current_iteration
    }

    fn contains_key(&self, instance_id: &str) -> bool {
        self.instance_data.contains_key(instance_id)
    }
}

pub struct InstanceManager {
    state_command_sender: tokio::sync::mpsc::Sender<StateManagerMsg>,
    instance_command_receiver: tokio::sync::mpsc::Receiver<InstanceManagerCommand>,
    instance_command_sender: tokio::sync::mpsc::Sender<InstanceManagerCommand>,
    outgoing_p2p_sender: tokio::sync::mpsc::Sender<NetMessage>,
    incoming_p2p_receiver: tokio::sync::mpsc::Receiver<NetMessage>,
    instances: InstanceCache,
    backlog: HashMap<String, BacklogData>,
    backlog_interval: tokio::time::Interval,
    event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
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
        ciphertext: Ciphertext,
    },
    Signature {
        message: Vec<u8>,
        label: Vec<u8>,
        scheme: ThresholdScheme,
        group: Group,
    },
    Coin {
        name: Vec<u8>,
        scheme: ThresholdScheme,
        group: Group,
    },
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
        result: Result<Vec<u8>, ProtocolError>,
    },

    UpdateInstanceStatus {
        instance_id: String,
        status: String,
    },
}

#[macro_export]
macro_rules! call_state_manager {
    ( $self:ident, $cmd:expr, $rtype:path ) => {{
        let _tmp = $self.call_state_manager($cmd).await;

        if _tmp.is_none() {
            info!("Got no response from state manager");
            return Err(Status::aborted(
                "Could not get a response from state manager",
            ));
        }

        if let Option::Some($rtype(s)) = _tmp {
            Option::Some(s)
        } else {
            Option::None
        }
    }};
}

impl InstanceManager {
    pub fn new(
        state_command_sender: tokio::sync::mpsc::Sender<StateManagerMsg>,
        instance_command_receiver: tokio::sync::mpsc::Receiver<InstanceManagerCommand>,
        instance_command_sender: tokio::sync::mpsc::Sender<InstanceManagerCommand>,
        outgoing_p2p_sender: tokio::sync::mpsc::Sender<NetMessage>,
        incoming_p2p_receiver: tokio::sync::mpsc::Receiver<NetMessage>,
        event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
    ) -> Self {
        return Self {
            state_command_sender,
            instance_command_receiver,
            instance_command_sender,
            outgoing_p2p_sender,
            incoming_p2p_receiver,
            instances: InstanceCache::new(None),
            backlog: HashMap::new(),
            backlog_interval: tokio::time::interval(tokio::time::Duration::from_secs(
                BACKLOG_CHECK_INTERVAL as u64,
            )),
            event_emitter_sender,
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
                                Some(_instance) => {
                                    _instance.set_result(result);
                                    self.instances.inform_of_termination(instance_id.clone());
                                },
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
                        is_total_order: _,
                        message_data
                    } = incoming_message.expect("The channel for incoming_message_receiver has been closed.");

                    let instance =  self.instances.get(&instance_id);

                    // First check, if an instance already exists for that message
                    match instance {
                        Some(_instance) => {
                            // If yes, forward the message to the instance. (ok if the following returns Err, it only means the instance has finished in the mean time)
                            let _ = _instance.send_message(message_data).await;
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

    pub async fn start<'a>(
        &mut self,
        instance_request: StartInstanceRequest,
    ) -> Result<String, ThresholdCryptoError> {
        // Create a unique instance_id for this instance
        let instance_id = assign_instance_id(&instance_request);

        match instance_request {
            StartInstanceRequest::Decryption { ciphertext } => {
                let key = self
                    .setup_instance(
                        ciphertext.get_scheme(),
                        ciphertext.get_group(),
                        &instance_id,
                        Option::None,
                    )
                    .await;

                if key.is_err() {
                    return Err(ThresholdCryptoError::Aborted(String::from("key not found")));
                }

                let key = Arc::new(key.unwrap().sk.clone());

                let (sender, receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

                let instance = Instance::new(
                    instance_id.clone(),
                    ciphertext.get_scheme(),
                    ciphertext.get_group().clone(),
                    sender,
                );

                // Create the new protocol instance
                let prot = ThresholdCipherProtocol::new(
                    key,
                    ciphertext,
                    receiver,
                    self.outgoing_p2p_sender.clone(),
                    self.event_emitter_sender.clone(),
                    instance_id.clone(),
                );

                self.instances.insert(instance_id.clone(), instance);

                // Start it in a new thread, so that the client does not block until the protocol is finished.
                Self::start_protocol(
                    prot,
                    instance_id.clone(),
                    self.instance_command_sender.clone(),
                );

                return Ok(instance_id.clone());
            }
            StartInstanceRequest::Signature {
                message,
                label,
                scheme,
                group,
            } => {
                let key = self
                    .setup_instance(scheme, &group, &instance_id, Option::None)
                    .await;

                if key.is_err() {
                    return Err(ThresholdCryptoError::Aborted(
                        key.as_ref().unwrap_err().to_string(),
                    ));
                }

                let key = Arc::new(key.unwrap().sk.clone());

                let (sender, receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

                let instance = Instance::new(instance_id.clone(), scheme, group.clone(), sender);

                // Create the new protocol instance
                let prot = ThresholdSignatureProtocol::new(
                    key,
                    Some(&message),
                    &label,
                    receiver,
                    self.outgoing_p2p_sender.clone(),
                    self.event_emitter_sender.clone(),
                    instance_id.clone(),
                );

                self.instances.insert(instance_id.clone(), instance);

                // Start it in a new thread, so that the client does not block until the protocol is finished.
                Self::start_protocol(
                    prot,
                    instance_id.clone(),
                    self.instance_command_sender.clone(),
                );

                return Ok(instance_id.clone());
            }
            StartInstanceRequest::Coin {
                name,
                scheme,
                group,
            } => {
                let key = self
                    .setup_instance(scheme, &group, &instance_id, Option::None)
                    .await;

                if key.is_err() {
                    return Err(ThresholdCryptoError::Aborted(
                        key.as_ref().unwrap_err().message().to_string(),
                    ));
                }

                let key = Arc::new(key.unwrap().sk.clone());

                let (sender, receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

                let instance = Instance::new(instance_id.clone(), scheme, group, sender);

                // Create the new protocol instance
                let prot = ThresholdCoinProtocol::new(
                    key,
                    &name,
                    receiver,
                    self.outgoing_p2p_sender.clone(),
                    self.event_emitter_sender.clone(),
                    instance_id.clone(),
                );

                self.instances.insert(instance_id.clone(), instance);

                // Start it in a new thread, so that the client does not block until the protocol is finished.
                Self::start_protocol(
                    prot,
                    instance_id.clone(),
                    self.instance_command_sender.clone(),
                );

                return Ok(instance_id.clone());
            }
        }
    }

    fn start_protocol(
        mut prot: (impl ThresholdProtocol + std::marker::Send + 'static),
        instance_id: String,
        sender: tokio::sync::mpsc::Sender<InstanceManagerCommand>,
    ) {
        tokio::spawn(async move {
            let result = prot.run().await;

            // Protocol terminated, update state with the result.
            info!("Instance {:?} finished", instance_id);

            while sender
                .send(InstanceManagerCommand::StoreResult {
                    instance_id: instance_id.clone(),
                    result: result.clone(),
                })
                .await
                .is_err()
            {
                // loop until transmission successful
                error!("Error storing result, retrying...");
                thread::sleep(time::Duration::from_millis(500)); // wait for 500ms before trying again
            }
        });
    }

    async fn _forward_backlogged_messages(&mut self, instance_id: String) {
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
            let _ = instance.send_message(msg.clone()).await;
        }

        self.backlog.remove(&instance_id);
    }

    async fn call_state_manager(
        &self,
        command: StateManagerCommand,
    ) -> Option<StateManagerResponse> {
        let (response_sender, response_receiver) = oneshot::channel::<StateManagerResponse>();

        let msg = if command.will_respond() {
            StateManagerMsg {
                command,
                responder: Option::Some(response_sender),
            }
        } else {
            StateManagerMsg {
                command,
                responder: Option::None,
            }
        };

        let wait_for_response = msg.responder.is_some();

        if self.state_command_sender.send(msg).await.is_err() {
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
        key_id: Option<String>,
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
            let key_result = call_state_manager!(
                self,
                StateManagerCommand::GetPrivateKeyByType {
                    scheme,
                    group: group.clone(),
                },
                StateManagerResponse::Key
            );

            if key_result.is_none() {
                error!("Got no response from state manager");
                return Err(Status::aborted(
                    "Could not get a response from state manager",
                ));
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
        StartInstanceRequest::Decryption { ciphertext } => {
            digest.process_array(ciphertext.get_ck());
            let h: &[u8] = &digest.hash()[..8];
            return hex::encode(h);
        }
        StartInstanceRequest::Signature {
            message,
            label: _,
            scheme: _,
            group: _,
        } => {
            /* PROBLEM: Hashing the whole
            message might become a bottleneck for big messages */
            digest.process_array(&message);
            let h: &[u8] = &digest.hash()[..8];
            return hex::encode(h);
        }
        StartInstanceRequest::Coin {
            name,
            scheme: _,
            group: _,
        } => {
            /* PROBLEM: Hashing the whole
            name might become a bottleneck for long names */
            digest.process_array(&name);
            let h: &[u8] = &digest.hash()[..8];
            return hex::encode(h);
        }
    }
}
