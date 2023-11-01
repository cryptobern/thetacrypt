use std::{collections::HashMap, sync::Arc};
use log::info;
use theta_protocols::interface::ProtocolError;
use theta_schemes::{interface::{ThresholdScheme, InteractiveThresholdSignature}};
use theta_proto::scheme_types::Group;
use tokio::sync::mpsc::Receiver;

use crate::{
    keychain::KeyChain,
    types::{Key},
};

#[derive(Debug)]
pub enum StateManagerCommand {
    // Returns the private keys that can be used with the given scheme and group
    GetPrivateKeyByType { 
        scheme: ThresholdScheme,
        group: Group,
    },
    // Returns all public keys that can be used for encryption.
    GetEncryptionKeys { 
    },
    PopFrostPrecomputation {
    },
    PushFrostPrecomputation {
        instance: InteractiveThresholdSignature
    }
}

impl StateManagerCommand {
    pub fn will_respond(&self) -> bool {
        match self {
            Self::GetEncryptionKeys {} => true,
            Self::GetPrivateKeyByType { scheme, group } => true,
            Self::PopFrostPrecomputation {} => true,
            Self::PushFrostPrecomputation { instance } => false,
        }
    }
}

#[derive(Debug)]
pub struct StateManagerMsg {
    pub command: StateManagerCommand,
    pub responder: Option<tokio::sync::oneshot::Sender<StateManagerResponse>>
}

#[derive(Debug)]
pub enum StateManagerResponse {
    Key(Result<Arc<Key>, String>),
    KeyVec(Vec<Arc<Key>>),
    Precomp(Option<InteractiveThresholdSignature>)
}

pub struct StateManager {
    keychain: KeyChain,
    message_receiver: Receiver<StateManagerMsg>,
}

impl StateManager {
    pub fn new(
        keychain: KeyChain,
        message_receiver: Receiver<StateManagerMsg>,
    ) -> Self {
        StateManager {
            keychain,
            message_receiver,
        }
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                command = self.message_receiver.recv() => { // Received a state-update command
                    let msg: StateManagerMsg = command.expect("All senders for state_command_receiver have been closed.");
                    
                    let cmd: StateManagerCommand = msg.command;
                    let responder = msg.responder;

                    match cmd {
                        StateManagerCommand::GetPrivateKeyByType { scheme, group } => {
                            let key_entry = self.keychain.get_key_by_scheme_and_group(scheme, group);
                            if let Option::Some(r) = responder {
                                r.send(StateManagerResponse::Key(key_entry)).expect("The receiver for responder in StateUpdateCommand::GetPrivateKeyByType has been closed.");
                            }
                        },
                        StateManagerCommand::GetEncryptionKeys { } => {
                            let key_entries = self.keychain.get_encryption_keys();
                            if let Option::Some(r) = responder {
                                r.send(StateManagerResponse::KeyVec(key_entries)).expect("The receiver for responder in StateUpdateCommand::GetEncryptionKeys has been closed.");
                            }
                        },
                        StateManagerCommand::PopFrostPrecomputation { } => {
                            let result = self.keychain.pop_precompute_result();
                            if let Option::Some(r) = responder {
                                r.send(StateManagerResponse::Precomp(result)).expect("The receiver for responder in StateUpdateCommand::PopFrostPrecomputation has been closed.");
                            }
                            info!("{} FROST precomputations stored", self.keychain.num_precomputations());
                        },
                        StateManagerCommand::PushFrostPrecomputation { instance } => {
                            let result = self.keychain.push_precompute_result(instance);
                        }
                        _ => unimplemented!()
                    }
                }
            }
        }
    }
}
