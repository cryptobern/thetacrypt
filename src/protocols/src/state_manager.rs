use std::{collections::HashMap, sync::Arc};
use schemes::{interface::{ThresholdScheme, InteractiveThresholdSignature}};
use thetacrypt_proto::scheme_types::Group;
use tokio::sync::mpsc::Receiver;

use crate::{
    keychain::KeyChain,
    types::{ProtocolError, Key},
};

// InstanceStatus describes the currenct state of a protocol instance. 
// The field result has meaning only when finished == true. 
#[derive(Debug, Clone)]
pub(crate) struct InstanceStatus {
    pub(crate) started: bool,
    pub(crate) finished: bool,
    pub(crate) result: Result<Vec<u8>, ProtocolError>, 
}

#[derive(Debug)]
pub(crate) enum StateUpdateCommand {
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
        responder: tokio::sync::oneshot::Sender< Result<Arc<Key>, String> >
    },
    // Returns all public keys that can be used for encryption.
    GetEncryptionKeys { 
        responder: tokio::sync::oneshot::Sender< Vec<Arc<Key>> >
    },
    PopFrostPrecomputation {
        responder: tokio::sync::oneshot::Sender<Option<InteractiveThresholdSignature>>,
        node_id: Option<usize> 
    },
    PushFrostPrecomputation {
        instance: InteractiveThresholdSignature,
        node_id: Option<usize>
    }
}

pub(crate) struct StateManager {
    keychain: KeyChain,
    state_command_receiver: Receiver<StateUpdateCommand>,
}

impl StateManager {
    pub(crate) fn new(
        keychain: KeyChain,
        state_command_receiver: Receiver<StateUpdateCommand>,
    ) -> Self {
        StateManager {
            keychain,
            state_command_receiver,
        }
    }

    pub(crate) async fn run(&mut self) {
        let mut instances_status_map: HashMap<String, InstanceStatus> = HashMap::new();
        loop {
            tokio::select! {
                state_update_command = self.state_command_receiver.recv() => { // Received a state-update command
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
                            let key_entry = self.keychain.get_key_by_scheme_and_group(scheme, group);
                            responder.send(key_entry).expect("The receiver for responder in StateUpdateCommand::GetPrivateKeyByType has been closed.");
                        },
                        StateUpdateCommand::GetEncryptionKeys { responder } => {
                            let key_entries = self.keychain.get_encryption_keys();
                            responder.send(key_entries).expect("The receiver for responder in StateUpdateCommand::GetEncryptionKeys has been closed.");
                        },
                        StateUpdateCommand::PopFrostPrecomputation { responder, node_id } => {
                            let result;
                            if let Option::Some(id) = node_id {
                                result = self.keychain.pop_node_precompute_result(&id);
                                
                            } else {
                                result = self.keychain.pop_precompute_result();
                            }
                            
                            responder.send(result).expect("The receiver for responder in StateUpdateCommand::PopFrostPrecomputation has been closed.");
                        },
                        StateUpdateCommand::PushFrostPrecomputation { instance, node_id } => {
                            let result;
                            if let Option::Some(id) = node_id {
                                result = self.keychain.push_node_precompute_result(id, instance);
                                
                            } else {
                                result = self.keychain.push_precompute_result(instance);
                            }

                            println!(">> {} FROST precomputations", self.keychain.num_precomputations());
                        }
                        _ => unimplemented!()
                    }
                }
            }
        }
    }
}
