use base64::{engine::general_purpose, Engine as _};
use log::{error, info};
use mcore::hash256::HASH256;
use serde::{Deserialize, Serialize};
use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::fmt::format;
use std::fs::{self, File};
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use theta_proto::scheme_types::PublicKeyEntry;
use theta_proto::scheme_types::{Group, ThresholdOperation, ThresholdScheme};

use crate::interface::{InteractiveThresholdSignature, Serializable};
use crate::scheme_types_impl::SchemeDetails;

use super::keys::{key2id, PrivateKeyShare, PublicKey};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KeyEntry {
    pub id: String,
    pub(crate) is_default: bool,
    pub sk: Option<PrivateKeyShare>,
    pub pk: PublicKey,
}

impl KeyEntry {
    pub fn to_string(&self) -> String {
        let mut postfix = String::from("");
        if self.sk.is_some() {
            postfix.push_str("<sk>");
        }

        let mut default_string = String::from("");
        if self.is_default {
            default_string.push_str(" (default)");
        }

        format!(
            "{} [{}/{}] {} {}",
            &self.id,
            self.pk.get_scheme().as_str_name(),
            self.pk.get_group().as_str_name(),
            postfix,
            default_string
        )
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct KeyChain {
    key_entries: HashMap<String, KeyEntry>,
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
                    let key = key.unwrap();
                    let id = kc.insert_private_key(key.clone());
                    if id.is_err() {
                        error!("Error inserting private key: {}", id.unwrap_err());
                    }

                    /*let id = id.unwrap();
                    if id != key.get_key_id() {
                        error!("Key id changed: {} - {}", key.get_key_id(), &id);
                    }*/
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
                    let id = kc.insert_public_key(key.unwrap());

                    if id.is_err() {
                        error!("Error inserting public key: {}", id.unwrap_err());
                    }

                    /*  let id = id.unwrap();
                    if id != key.unwrap().get_key_id() {
                        error!("Key id changed: {} - {}", key.unwrap().get_key_id(), &id);
                    }*/
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
        let ks: Vec<SerializedKeyEntry> = serde_json::from_str(&key_chain_str)?;
        let k: KeyChain = ks.into();
        self.key_entries = k.key_entries;
        self.filename = Some(filename.clone());
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

    pub fn import_public_keys(&mut self, public_keys: &[PublicKeyEntry]) -> Result<(), String> {
        for entry in public_keys {
            let key = PublicKey::from_bytes(&entry.key);
            if key.is_ok() {
                let id = self.insert_public_key(key.unwrap());
                if id.is_err() {
                    return Err(String::from("Error importing public key"));
                }

                println!("Imported public key {}", id.unwrap());
            } else {
                return Err(String::from("Error importing public key"));
            }
        }

        Ok(())
    }

    pub fn to_string(&self) -> String {
        let mut encryption_keys = self.get_encryption_keys();
        encryption_keys.sort_by(|a, b| a.pk.get_scheme().partial_cmp(&b.pk.get_scheme()).unwrap());
        let mut signature_keys = self.get_signing_keys();
        signature_keys.sort_by(|a, b| a.pk.get_scheme().partial_cmp(&b.pk.get_scheme()).unwrap());
        let mut coin_keys = self.get_coin_keys();
        coin_keys.sort_by(|a, b| a.pk.get_scheme().partial_cmp(&b.pk.get_scheme()).unwrap());
        let mut output = String::new();

        output.push_str("\n---------------\n");
        output.push_str("Key Chain\n");
        output.push_str("---------------\n");

        output.push_str("\nEncryption:\n");
        for key in &encryption_keys {
            output.push_str(&key.to_string());
            output.push_str("\n");
        }

        output.push_str("\nSignatures:\n");
        for key in &signature_keys {
            output.push_str(&key.to_string());
            output.push_str("\n");
        }

        output.push_str("\nCoins:\n");
        for key in &coin_keys {
            output.push_str(&key.to_string());
            output.push_str("\n");
        }

        output
    }

    // Inserts a key to the key_chain and returns the unique id of the key
    // The function, and eventually the KeyChain, gets ownership of the key.
    // A key is_default_for_scheme_and_group if it is the first key created for its scheme and group.
    // A key is_default_for_operation if it is the first key created for its operation.
    pub fn insert_private_key(&mut self, key: PrivateKeyShare) -> Result<String, String> {
        let key_id = key2id(&key.get_public_key());

        if key_id.ne(key.get_key_id()) {
            error!("Key does not match id");
            return Err(String::from("Key id does not match key"));
        }

        if self
            .key_entries
            .iter()
            .any(|e| e.0.eq(&key_id) && e.1.sk.is_some())
        {
            return Err(String::from("KEYC: A key wit key_id: already exists."));
        }

        let operation = key.get_scheme().get_operation();
        let matching_keys: Vec<(&String, &mut KeyEntry)> = self
            .key_entries
            .iter_mut()
            .filter(|e| {
                e.1.sk.is_some()
                    && e.1.sk.as_ref().unwrap().get_scheme().get_operation() == operation
            })
            .collect();

        let mut is_default = true;
        for _k in matching_keys {
            _k.1.is_default = false;
            is_default = false;
        }

        let entry = self.key_entries.get(&key_id);
        if entry.is_some() {
            self.key_entries.remove_entry(&key_id);
        }

        self.key_entries.insert(
            key_id.clone(),
            KeyEntry {
                id: key_id.clone(),
                is_default,
                pk: key.get_public_key(),
                sk: Some(key),
            },
        );

        Ok(key_id)
    }

    pub fn insert_public_key(&mut self, key: PublicKey) -> Result<String, String> {
        let key_id = key2id(&key);

        if key_id.ne(key.get_key_id()) {
            error!("Key does not match id");
            return Err(String::from("Key id does not match key"));
        }

        if self.key_entries.iter().any(|e| e.0.eq(&key_id)) {
            return Err(String::from("A key with same key id already exists."));
        }

        let operation = key.get_scheme().get_operation();
        let is_default = !self
            .key_entries
            .iter()
            .any(|e| e.1.pk.get_scheme().get_operation() == operation);

        self.key_entries.insert(
            key_id.clone(),
            KeyEntry {
                id: key_id.clone(),
                is_default,
                sk: None,
                pk: key,
            },
        );
        Ok(key_id)
    }

    // Return the matching key with the given key_id, or an error if no key with key_id exists.
    pub fn get_key_by_id(&self, id: &String) -> Result<KeyEntry, String> {
        if self.key_entries.contains_key(id) == false {
            error!("No entry for id {}", &id);
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
    ) -> Result<KeyEntry, String> {
        let matching_key_entries: Vec<(&String, &KeyEntry)> = self
            .key_entries
            .iter()
            .filter(|&entry| entry.1.pk.get_scheme() == scheme && group.eq(entry.1.pk.get_group()))
            .collect();
        return match matching_key_entries.len() {
            0 => Err(String::from("No key matches the given scheme and group.")),
            1 => Ok(matching_key_entries[0].1.clone()),
            _ => {
                let default_key_entries: Vec<(&String, &KeyEntry)> = matching_key_entries
                    .iter()
                    .filter(|&entry| entry.1.is_default)
                    .map(|e| *e)
                    .collect();
                match default_key_entries.len() {
                    0 => {
                        error!("One key should always be specified as default.");
                        Err(String::from("Could not find a default key for this scheme. Please specify a key id."))
                    }
                    1 => Ok(default_key_entries[0].1.clone()),
                    _ => {
                        error!("No more than one key should always be specified as default.");
                        Err(String::from("Could not select a default key for this scheme. Please specify a key id."))
                    }
                }
            }
        };
    }

    // Return all available keys for the given operation
    fn get_keys_by_operation(&self, operation: ThresholdOperation) -> Vec<&KeyEntry> {
        let matching_key_entries: Vec<&KeyEntry> = self
            .key_entries
            .iter()
            .filter(|&entry| entry.1.pk.get_scheme().get_operation() == operation)
            .map(|e| e.1)
            .collect();
        matching_key_entries
    }

    pub fn get_encryption_keys(&self) -> Vec<&KeyEntry> {
        return self.get_keys_by_operation(ThresholdOperation::Encryption);
    }

    pub fn get_signing_keys(&self) -> Vec<&KeyEntry> {
        return self.get_keys_by_operation(ThresholdOperation::Signature);
    }

    pub fn get_coin_keys(&self) -> Vec<&KeyEntry> {
        return self.get_keys_by_operation(ThresholdOperation::Coin);
    }

    pub fn list_public_keys(&self) -> Vec<Arc<PublicKeyEntry>> {
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
