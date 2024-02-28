use std::{collections::HashMap, path::PathBuf, sync::Arc};

use log::{error, info};
use theta_proto::{
    scheme_types::PublicKeyEntry,
    scheme_types::{Group, ThresholdScheme},
};
use theta_schemes::{
    dl_schemes::signatures::frost::PublicCommitment,
    interface::InteractiveThresholdSignature,
    keys::key_store::{KeyEntry, KeyStore},
};

pub struct KeyManager {
    command_receiver: tokio::sync::mpsc::Receiver<KeyManagerCommand>,
    keystore: KeyStore,
    frost_precomputes: Vec<HashMap<u16, PublicCommitment>>,
}

#[derive(Debug)]
pub enum KeyManagerCommand {
    // Returns a list of keys
    ListAvailableKeys {
        responder: tokio::sync::oneshot::Sender<Vec<Arc<PublicKeyEntry>>>,
    },
    // Returns key matching the id
    GetKeyById {
        id: String,
        responder: tokio::sync::oneshot::Sender<Result<Arc<KeyEntry>, String>>,
    },
    // Returns the private keys that can be used with the given scheme and group
    GetKeyBySchemeAndGroup {
        scheme: ThresholdScheme,
        group: Group,
        responder: tokio::sync::oneshot::Sender<Result<Arc<KeyEntry>, String>>,
    },
    PopFrostPrecomputation {
        responder: tokio::sync::oneshot::Sender<Option<HashMap<u16, PublicCommitment>>>,
    },
    PushFrostPrecomputations {
        precomputations: Vec<HashMap<u16, PublicCommitment>>,
    },
}

impl KeyManager {
    pub fn new(
        keychain_path: PathBuf,
        command_receiver: tokio::sync::mpsc::Receiver<KeyManagerCommand>,
    ) -> Self {
        let mut keystore = KeyStore::new();
        if let Err(e) = keystore.load(&keychain_path) {
            error!(
                "Error loading keystore '{}': {}",
                keychain_path.display(),
                e.to_string()
            );
        };

        info!("Keychain loaded successfully");

        Self {
            command_receiver,
            keystore,
            frost_precomputes: Vec::new(),
        }
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                command = self.command_receiver.recv() => {
                    let cmd = command.expect("");
                    match cmd {
                        KeyManagerCommand::ListAvailableKeys{
                            responder
                        } => {
                            let result = self.keystore.list_public_keys();
                            responder.send(result).expect("The receiver for responder in KeyManagerCommand::GetInstanceResult has been closed.");
                        },
                        KeyManagerCommand::PopFrostPrecomputation {
                            responder
                        } => {
                            let result = self.pop_precomputation();

                            responder.send(result).expect("The receiver for responder in KeyManagerCommand::PopFrostPrecomputation has been closed.");

                            info!("{} FROST precomputations left", self.num_precomputations());
                        },
                        KeyManagerCommand::PushFrostPrecomputations { precomputations } => {
                            self.append_precomputations(precomputations);
                        },
                        KeyManagerCommand::GetKeyById {id, responder} => {
                            info!("Searching for key with id {}", &id);
                            let result = self.keystore.get_key_by_id(&id);

                            if result.is_ok() {
                                responder.send(Ok(Arc::new(result.unwrap()))).expect("The receiver for responder in KeyManagerCommand::PopFrostPrecomputation has been closed.");
                            } else {
                                responder.send(Err(result.unwrap_err().to_string())).expect("The receiver for responder in KeyManagerCommand::PopFrostPrecomputation has been closed.");
                            }
                        },
                        KeyManagerCommand::GetKeyBySchemeAndGroup { scheme, group, responder } => {
                            let result = self.keystore.get_key_by_scheme_and_group(scheme, group);

                            if result.is_ok() {
                                responder.send(Ok(Arc::new(result.unwrap()))).expect("The receiver for responder in KeyManagerCommand::PopFrostPrecomputation has been closed.");
                            } else {
                                responder.send(Err(result.unwrap_err())).expect("The receiver for responder in KeyManagerCommand::PopFrostPrecomputation has been closed.");
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn num_precomputations(&self) -> usize {
        return self.frost_precomputes.len();
    }

    pub fn append_precomputations(&mut self, precomputations: Vec<HashMap<u16, PublicCommitment>>) {
        self.frost_precomputes = [precomputations, self.frost_precomputes.clone()].concat();
    }

    pub fn pop_precomputation(&mut self) -> Option<HashMap<u16, PublicCommitment>> {
        self.frost_precomputes.pop()
    }
}
