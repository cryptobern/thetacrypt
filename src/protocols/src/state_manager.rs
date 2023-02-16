use std::collections::HashMap;

use tokio::sync::mpsc::Receiver;

use crate::{types::{InstanceStatus, StateUpdateCommand, ProtocolError}, keychain::KeyChain};

pub(crate) struct StateManager {
    keychain: KeyChain,
    state_command_receiver: Receiver<StateUpdateCommand>
}

impl StateManager {
    pub(crate) fn new(keychain: KeyChain, state_command_receiver: Receiver<StateUpdateCommand>) -> Self {
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
                            responder.send(key_entries).expect("The receiver for responder in StateUpdateCommand::GetPrivateKeyByType has been closed.");
                        },
                        _ => unimplemented!()
                    }
                }
            }
        }
    }
}