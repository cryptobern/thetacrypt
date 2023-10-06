use serde::{Deserialize, Serialize};
use theta_proto::scheme_types::{ThresholdScheme, Group};
use std::collections::HashMap;
use std::fmt::format;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use crate::types::Key;
use theta_schemes::{interface::InteractiveThresholdSignature, keys::PrivateKey};

pub struct KeyChain {
    key_entries: HashMap<String, Arc<Key>>,
    frost_precomputes: Vec<InteractiveThresholdSignature>
}

// KeyChainSerializable is the same as KeyChain without the shared references.
// It is meant to be used only as an intermediate struct when serializing/deserializing a KeyChain struct.
#[derive(Serialize, Deserialize)]
struct KeyChainSerializable {
    key_entries: HashMap<String, Key>,
}

impl KeyChainSerializable {
    fn new() -> Self {
        KeyChainSerializable {
            key_entries: HashMap::new()
        }
    }
}

impl From<&KeyChain> for KeyChainSerializable {
    fn from(k: &KeyChain) -> Self {
        let mut ks = KeyChainSerializable::new();
        for entry in k.key_entries.iter() {
            ks.key_entries.insert((*entry.0).clone(), (**entry.1).clone());
        }
        ks
    }
}

impl Into<KeyChain> for KeyChainSerializable {
    fn into(self) -> KeyChain {
        let mut k = KeyChain::new();
        for entry in self.key_entries {
            k.key_entries.insert(entry.0, Arc::new(entry.1));
        }
        k
    }
}

#[derive(PartialEq, Eq)]
enum Operation {
    Encryption,
    Sign,
    Coin,
}

fn get_operation_of_scheme(scheme: &ThresholdScheme) -> Operation {
    match scheme {
        ThresholdScheme::Bz03 => Operation::Encryption,
        ThresholdScheme::Sg02 => Operation::Encryption,
        ThresholdScheme::Bls04 => Operation::Sign,
        ThresholdScheme::Cks05 => Operation::Coin,
        ThresholdScheme::Frost => Operation::Sign,
        ThresholdScheme::Sh00 => Operation::Sign,
        _ => unimplemented!(),
    }
}

impl KeyChain {
    pub fn new() -> Self {
        KeyChain {
            key_entries: HashMap::new(),
            frost_precomputes: Vec::new()
        }
    }

    pub fn from_file(filename: &PathBuf) -> std::io::Result<Self> {
        let key_chain_str = fs::read_to_string(filename)?;
        let ks: KeyChainSerializable = serde_json::from_str(&key_chain_str)?;
        let k: KeyChain = ks.into();
        Ok(k)
    }

    pub fn to_file(&self, filename: &str) -> std::io::Result<()> {
        let ks = KeyChainSerializable::from(self);
        let file = File::create(filename)?;
        serde_json::to_writer(file, &ks)?;
        Ok(())
    }

    pub fn num_precomputations(&self) -> usize {
        return self.frost_precomputes.len();
    }

    // Inserts a key to the key_chain. A key_id must be given and must be unique among all keys (regardless of the key scheme).
    // The funcion, and eventually the KeyChain, gets ownership of the key.
    // A key is_default_for_scheme_and_group if it is the first key created for its scheme and group.
    // A key is_default_for_operation if it is the first key created for its operation.
    pub fn insert_key(&mut self, key: PrivateKey, key_id: String) -> Result<(), String> {
        if self.key_entries.iter().any(|e| e.0.eq(&key_id)) {
            return Err(String::from("KEYC: A key wit key_id: already exists."));
        }

        let scheme = key.get_scheme();
        let group = key.get_group();
        let is_default_for_scheme_and_group = !self
            .key_entries
            .iter()
            .any(|e| e.1.sk.get_scheme() == scheme && e.1.sk.get_group() == group);
        let operation = get_operation_of_scheme(&key.get_scheme());
        let is_default_for_operation = !self
            .key_entries
            .iter()
            .any(|e| get_operation_of_scheme(&e.1.sk.get_scheme()) == operation);

        self.key_entries.insert(key_id.clone(), Arc::new(Key {
            id: key_id,
            is_default_for_scheme_and_group,
            is_default_for_operation,
            sk: key,
        }));
        Ok(())
    }

    pub fn append_precompute_results(&mut self, instances: &mut Vec<InteractiveThresholdSignature>) {
        self.frost_precomputes.append(instances);
    }

    pub fn push_precompute_result(&mut self, instance: InteractiveThresholdSignature) {
        self.frost_precomputes.push(instance);
        self.frost_precomputes.sort_by(|a, b| a.get_label().cmp(&b.get_label()))
    }

    pub fn pop_precompute_result(&mut self) -> Option<InteractiveThresholdSignature> {
        self.frost_precomputes.pop()
    }

    // Return the matching key with the given key_id, or an error if no key with key_id exists.
    pub fn get_key_by_id(&self, id: &String) -> Result<Arc<Key>, String> {
        if self.key_entries.contains_key(id) == false {
            return Err(format!("Could not find a key with the given key_id '{}'", id));
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
    ) -> Result<Arc<Key>, String> {
        let matching_key_entries: Vec<(&String, &Arc<Key>)> = self
            .key_entries
            .iter()
            .filter(|&entry| entry.1.sk.get_scheme() == scheme && entry.1.sk.get_group() == group)
            .collect();
        return match matching_key_entries.len() {
            0 => Err(String::from("No key matches the given scheme and group.")),
            1 => Ok(Arc::clone(&matching_key_entries[0].1)),
            _ => {
                let default_key_entries: Vec<(&String, &Arc<Key>)> = matching_key_entries
                    .iter()
                    .filter(|&entry| entry.1.is_default_for_scheme_and_group)
                    .map(|e| *e)
                    .collect();
                match default_key_entries.len() {
                    0 => {
                        print!(">> KEYC: ERROR: One key should always be specified as default.");
                        Err(String::from("Could not find a default key for this scheme. Please specify a key id."))
                    }
                    1 => Ok(Arc::clone(&default_key_entries[0].1)),
                    _ => {
                        print!(">> KEYC: ERROR: No more than one key should always be specified as default.");
                        Err(String::from("Could not select a default key for this scheme. Please specify a key id."))
                    }
                }
            }
        };
    }

    // Return all available keys for the given operation
    fn get_keys_by_operation(&self, operation: Operation) -> Vec<Arc<Key>> {
        let matching_key_entries: Vec<Arc<Key>> = self
            .key_entries
            .iter()
            .filter(|&entry| get_operation_of_scheme(&entry.1.sk.get_scheme()) == operation)
            .map(|e| Arc::clone(e.1))
            .collect();
        matching_key_entries
    }

    pub fn get_encryption_keys(&self) -> Vec<Arc<Key>> {
        return self.get_keys_by_operation(Operation::Encryption);
    }

    pub fn get_signing_keys(&self) -> Vec<Arc<Key>> {
        return self.get_keys_by_operation(Operation::Sign);
    }

    pub fn get_coin_keys(&self) -> Vec<Arc<Key>> {
        return self.get_keys_by_operation(Operation::Coin);
    }
}
