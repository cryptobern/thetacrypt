use base64::{engine::general_purpose, Engine as _};
use log::{error, info};
use mcore::hash256::HASH256;
use serde::{Deserialize, Serialize};
use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::sync::Arc;
use theta_proto::protocol_types::PublicKeyEntry;
use theta_proto::scheme_types::{Group, ThresholdOperation, ThresholdScheme};

use crate::interface::{InteractiveThresholdSignature, Serializable};
use crate::scheme_types_impl::SchemeDetails;

use super::keys::{PrivateKeyShare, PublicKey};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KeyEntry {
    pub id: String,
    pub(crate) is_default: bool,
    pub sk: Option<PrivateKeyShare>,
    pub pk: PublicKey,
}

#[derive(PartialEq, Eq, Debug)]
pub struct KeyChain {
    key_entries: HashMap<String, Arc<KeyEntry>>,
    filename: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
struct SerializedKeyEntry {
    pub id: String,
    pub key_type: String,
    pub group: String,
    pub scheme: String,
    pub operation: String,
    pub key: String,
}

impl From<Vec<SerializedKeyEntry>> for KeyChain {
    fn from(value: Vec<SerializedKeyEntry>) -> Self {
        let mut kc = Self::new();
        let secret_string = String::from("secret");
        for entry in value {
            match entry.key_type {
                secret_string => {
                    let key = PrivateKeyShare::from_pem(&entry.key);
                    if key.is_err() {
                        error!(
                            "Error deserializing private key share: {}",
                            key.unwrap_err().to_string()
                        );
                        continue;
                    }
                    kc.insert_private_key(key.unwrap());
                }
                _ => {
                    let key = PublicKey::from_pem(&entry.key);
                    if key.is_err() {
                        error!(
                            "Error deserializing public key: {}",
                            key.unwrap_err().to_string()
                        );
                        continue;
                    }
                    kc.insert_public_key(key.unwrap());
                }
            }
        }

        kc
    }
}

impl KeyChain {
    pub fn new() -> Self {
        KeyChain {
            key_entries: HashMap::new(),
            filename: Option::None,
        }
    }

    pub fn load(&mut self, filename: &PathBuf) -> std::io::Result<()> {
        let key_chain_str = fs::read_to_string(filename)?;
        let node_keys: HashMap<String, String> = serde_json::from_str(&key_chain_str)?;
        self.key_entries.clear();
        self.filename = Some(filename.clone());

        for key in node_keys {
            let result = PrivateKeyShare::from_pem(&key.1);
            if let Ok(k) = result {
                if let Err(_) = self.insert_private_key(k.clone()) {
                    error!("Importing key '{}' failed", key.0);
                    return Err(Error::new(ErrorKind::InvalidData, "Importing key failed"));
                }

                info!(
                    "Imported key '{}' {} {}",
                    key.0,
                    k.get_group().as_str_name(),
                    k.get_scheme().as_str_name()
                );
            }
        }
        Ok(())
    }

    pub fn from_file(filename: &PathBuf) -> std::io::Result<Self> {
        let key_chain_str = fs::read_to_string(filename)?;
        let ks: Vec<SerializedKeyEntry> = serde_json::from_str(&key_chain_str)?;
        let k: KeyChain = ks.into();
        Ok(k)
    }

    pub fn to_file(&self, filename: &str) -> std::io::Result<()> {
        let mut keys = Vec::new();

        for (id, key) in &self.key_entries {
            keys.push(SerializedKeyEntry {
                id: id.clone(),
                key_type: match key.sk.is_some() {
                    true => String::from("secret"),
                    false => String::from("public"),
                },
                group: key.pk.get_group().as_str_name().to_string(),
                scheme: key.pk.get_scheme().as_str_name().to_string(),
                operation: key.pk.get_operation().as_str_name().to_string(),
                key: match key.sk.is_some() {
                    true => key.sk.as_ref().unwrap().pem().unwrap(),
                    false => key.pk.pem().unwrap(),
                },
            });
        }

        let serialized = serde_json::to_string(&keys).unwrap();
        fs::write(filename, serialized)?;

        Ok(())
    }

    // Inserts a key to the key_chain and returns the unique id of the key
    // The function, and eventually the KeyChain, gets ownership of the key.
    // A key is_default_for_scheme_and_group if it is the first key created for its scheme and group.
    // A key is_default_for_operation if it is the first key created for its operation.
    pub fn insert_private_key(&mut self, key: PrivateKeyShare) -> Result<String, String> {
        let bytes = key.get_public_key().to_bytes().unwrap();
        let mut hash = HASH256::new();
        hash.process_array(&bytes);
        let key_id = general_purpose::URL_SAFE.encode(hash.hash());

        if self
            .key_entries
            .iter()
            .any(|e| e.0.eq(&key_id) && e.1.sk.is_some())
        {
            return Err(String::from("KEYC: A key wit key_id: already exists."));
        }

        let scheme = key.get_scheme();
        let group = key.get_group();
        let operation = key.get_scheme().get_operation();
        let is_default = !self
            .key_entries
            .iter()
            .filter(|e| e.1.sk.is_some())
            .any(|e| e.1.sk.as_ref().unwrap().get_scheme().get_operation() == operation);

        let entry = self.key_entries.iter().find(|e| e.0.eq(&key_id));
        if entry.is_some() {
            //self.key_entries.remove_entry(key_id);
        }

        self.key_entries.insert(
            key_id.clone(),
            Arc::new(KeyEntry {
                id: key_id.clone(),
                is_default,
                pk: key.get_public_key(),
                sk: Some(key),
            }),
        );

        Ok(key_id)
    }

    pub fn insert_public_key(&mut self, key: PublicKey) -> Result<String, String> {
        let bytes = key.to_bytes().unwrap();
        let mut hash = HASH256::new();
        hash.process_array(&bytes);
        let key_id = general_purpose::URL_SAFE.encode(hash.hash());

        if self.key_entries.iter().any(|e| e.0.eq(&key_id)) {
            return Err(String::from("KEYC: A key wit key_id: already exists."));
        }

        let scheme = key.get_scheme();
        let group = key.get_group();
        let operation = key.get_scheme().get_operation();
        let is_default = !self
            .key_entries
            .iter()
            .any(|e| e.1.pk.get_scheme().get_operation() == operation);

        self.key_entries.insert(
            key_id.clone(),
            Arc::new(KeyEntry {
                id: key_id.clone(),
                is_default,
                sk: None,
                pk: key,
            }),
        );
        Ok(key_id)
    }

    // Return the matching key with the given key_id, or an error if no key with key_id exists.
    pub fn get_key_by_id(&self, id: &String) -> Result<Arc<KeyEntry>, String> {
        if self.key_entries.contains_key(id) == false {
            return Err(format!(
                "Could not find a key with the given key_id '{}'",
                id
            ));
        }

        return Ok(self.key_entries.get(id).unwrap().clone());
    }

    // First filter all keys and keep those that match the given scheme and group.
    // If there is no matching key, return an error.
    // If there is only one, return it.
    // Otherwise, return the 'default' key among the matching ones (there should be only one).
    pub fn get_key_by_scheme_and_group(
        &self,
        scheme: ThresholdScheme,
        group: Group,
    ) -> Result<Arc<KeyEntry>, String> {
        let matching_key_entries: Vec<(&String, &Arc<KeyEntry>)> = self
            .key_entries
            .iter()
            .filter(|&entry| entry.1.pk.get_scheme() == scheme && group.eq(entry.1.pk.get_group()))
            .collect();
        return match matching_key_entries.len() {
            0 => Err(String::from("No key matches the given scheme and group.")),
            1 => Ok(Arc::clone(&matching_key_entries[0].1)),
            _ => {
                let default_key_entries: Vec<(&String, &Arc<KeyEntry>)> = matching_key_entries
                    .iter()
                    .filter(|&entry| entry.1.is_default)
                    .map(|e| *e)
                    .collect();
                match default_key_entries.len() {
                    0 => {
                        error!("One key should always be specified as default.");
                        Err(String::from("Could not find a default key for this scheme. Please specify a key id."))
                    }
                    1 => Ok(Arc::clone(&default_key_entries[0].1)),
                    _ => {
                        error!("No more than one key should always be specified as default.");
                        Err(String::from("Could not select a default key for this scheme. Please specify a key id."))
                    }
                }
            }
        };
    }

    // Return all available keys for the given operation
    fn get_keys_by_operation(&self, operation: ThresholdOperation) -> Vec<Arc<KeyEntry>> {
        let matching_key_entries: Vec<Arc<KeyEntry>> = self
            .key_entries
            .iter()
            .filter(|&entry| entry.1.pk.get_scheme().get_operation() == operation)
            .map(|e| Arc::clone(e.1))
            .collect();
        matching_key_entries
    }

    pub fn get_encryption_keys(&self) -> Vec<Arc<KeyEntry>> {
        return self.get_keys_by_operation(ThresholdOperation::Encryption);
    }

    pub fn get_signing_keys(&self) -> Vec<Arc<KeyEntry>> {
        return self.get_keys_by_operation(ThresholdOperation::Signature);
    }

    pub fn get_coin_keys(&self) -> Vec<Arc<KeyEntry>> {
        return self.get_keys_by_operation(ThresholdOperation::Coin);
    }

    pub fn list_keys(&self) -> Vec<Arc<PublicKeyEntry>> {
        let mut keys = Vec::new();
        let it = self
            .key_entries
            .iter()
            .map(|entry| PublicKeyEntry {
                id: entry.1.id.clone(),
                operation: entry.1.pk.get_operation().into(),
                scheme: entry.1.pk.get_scheme().into(),
                group: (*entry.1.pk.get_group()).into(),
                key: entry.1.pk.to_bytes().unwrap(),
            })
            .for_each(|i| keys.push(Arc::new(i)));

        keys
    }
}
