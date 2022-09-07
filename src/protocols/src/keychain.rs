use std::{collections::{HashMap, HashSet}, fs::{self, File}, error::Error};
use cosmos_crypto::{keys::{PrivateKey, PublicKey}, interface::{Ciphertext}, proto::scheme_types::ThresholdScheme};
use cosmos_crypto::proto::scheme_types::Group;
// use serde::{Serialize, Deserialize, Serializer, ser::{SerializeSeq, SerializeStruct}};
use std::io::Write;

use crate::proto::protocol_types;


// #[derive(Serialize, Deserialize)]
pub struct KeyChain {
    key_entries: Vec<PrivateKeyEntry>,
}

// #[derive(Serialize, Deserialize, Clone)]
pub struct PrivateKeyEntry{
    pub id: String,
    is_default_for_scheme_and_group: bool,
    is_default_for_operation: bool,
    pub key: cosmos_crypto::keys::PrivateKey
}

#[derive(PartialEq, Eq)]
enum Operation {
    Encryption,
    Sign,
    Coin
}

fn get_operation_of_scheme(scheme: &ThresholdScheme) -> Operation {
    match scheme {
        ThresholdScheme::Bz03 => Operation::Encryption,
        ThresholdScheme::Sg02 => Operation::Encryption,
        ThresholdScheme::Bls04 => Operation::Sign,
        ThresholdScheme::Cks05 => Operation::Coin,
        ThresholdScheme::Frost => Operation::Sign,
        ThresholdScheme::Sh00 => Operation::Sign,
        _ => unimplemented!()
    }
}

impl KeyChain {
    
    pub fn new() -> Self {
        KeyChain {
            key_entries: Vec::new(),
        }
    }

    // pub fn from_file(filename: &str) -> std::io::Result<Self> {
    //     let key_chain_str = fs::read_to_string(filename)?;
    //     let key_chain: KeyChain = serde_json::from_str(&key_chain_str)?; 
    //     Ok(key_chain)
    // }

    // pub fn to_file(&self, filename: &str) -> std::io::Result<()> {
    //     let serialized = serde_json::to_string(&self)?;
    //     let mut file = File::create(filename)?;
    //     writeln!(&mut file, "{}", serialized)?;
    //     Ok(())
    // }

    // Inserts a key to the key_chain. A key_id must be given and must be unique among all keys (regardless of the key scheme).
    // A key is_default_for_scheme_and_group if it is the first key created for its scheme and group
    // A key is_default_for_operation if it is the first key created for its operation
    pub fn insert_key(&mut self, key: PrivateKey, key_id: String) -> Result<(), String> {
        if self.key_entries
                .iter()
                .any(|entry| entry.id == key_id) 
        {
            return Err(String::from("KEYC: A key wit key_id: already exists."));
        }
        let scheme = key.get_scheme();
        let group = key.get_group();
        let is_default_for_scheme_and_group = ! self.key_entries
                                                     .iter()
                                                     .any(|entry| entry.key.get_scheme() == scheme && entry.key.get_group() == group);
        let operation = get_operation_of_scheme(&key.get_scheme());
        let is_default_for_operation = ! self.key_entries
                                              .iter()
                                              .any(|entry| get_operation_of_scheme(&entry.key.get_scheme()) == operation);
    
        self.key_entries.push(PrivateKeyEntry{ id: key_id, is_default_for_scheme_and_group, is_default_for_operation, key });
        Ok(())
    }
 
    // Return the matching key with the given key_id, or an error if no key with key_id exists.
    pub fn get_key_by_id(&self, id: &String) -> Result<PrivateKeyEntry, String> {
        let key_entries_mathcing_id: Vec<&PrivateKeyEntry> = self.key_entries
                                                     .iter()
                                                     .filter(|&entry| entry.id == *id)
                                                     .collect();
        match key_entries_mathcing_id.len(){
            0 => {
                Err(String::from("Could not find a key with the given key_id: {key_id}."))
            },
            1 => {
                Ok((*key_entries_mathcing_id[0]).clone())
            },
            _ => {
                print!(">> KEYC: ERROR: More than one keys with the same id were found. key_id: {id}.");
                Err(String::from("More than one keys with key_id: {key_id} were found."))
            }
        }
    }

    // First filter all keys and keep those that match the given scheme and group.
    // If there is no matching key, return an error.
    // If there is only one, return it.
    // Otherwise, return the 'default' key among the matching ones (there should be only one).-
    pub fn get_key_by_type(&self, scheme: ThresholdScheme, group: Group) -> Result<PrivateKeyEntry, String> {
        let matching_key_entries: Vec<&PrivateKeyEntry> = self.key_entries
            .iter()
            .filter(|&entry| entry.key.get_scheme() == scheme && entry.key.get_group() == group)
            .collect();
        return match matching_key_entries.len(){
            0 => {
                Err(String::from("No key matches the given scheme anf group."))
            },
            1 => {
                Ok((*matching_key_entries[0]).clone())
            },
            _ => {
                let default_key_entries: Vec<&PrivateKeyEntry> = matching_key_entries
                                                        .iter()
                                                        .filter(|&entry| entry.is_default_for_scheme_and_group)
                                                        .map(|e| *e)
                                                        .collect();
                match default_key_entries.len() {
                    0 => {
                        print!(">> KEYC: ERROR: One key should always be specified as default.");
                        Err(String::from("Could not find a default key for this scheme. Please specify a key id."))
                    },
                    1 => {
                        Ok((*default_key_entries[0]).clone())
                    },
                    _ => {
                        print!(">> KEYC: ERROR: No more thatn one key should always be specified as default.");
                        Err(String::from("Could not select a default key for this scheme. Please specify a key id."))
                    }
                }     
            }
        }
    }

    pub fn get_public_keys_for_encryption(&self) -> Result<Vec<protocol_types::PublicKeyEntry>, String> {
        self.get_public_keys_for_operation(Operation::Encryption)
    }
    
    pub fn get_public_keys_for_signature(&self) -> Result<Vec<protocol_types::PublicKeyEntry>, String> {
        self.get_public_keys_for_operation(Operation::Sign)
    }
    
    pub fn get_public_keys_for_coin(&self) -> Result<Vec<protocol_types::PublicKeyEntry>, String> {
        self.get_public_keys_for_operation(Operation::Coin)
    }

    fn get_public_keys_for_operation(&self, operation: Operation) -> Result<Vec<protocol_types::PublicKeyEntry>, String> {
        let matching_public_key_entries: Result<Vec<protocol_types::PublicKeyEntry>, _> = 
            self
            .key_entries
            .iter()
            .filter(|&entry| get_operation_of_scheme(&entry.key.get_scheme()) == operation )
            .map(|e| self.get_public_key_entry(e) )
            .collect();
        matching_public_key_entries
    }

    // Convert from PrivateKeyEntry to protocol_types::PublicKeyEntry
    fn get_public_key_entry(&self, key_entry: &PrivateKeyEntry) -> Result<protocol_types::PublicKeyEntry, String> {
        let key_ser = key_entry.key
                                        .get_public_key()
                                        .serialize()
                                        .map_err( |err| format!("Serialization for key {:?} failed.", key_entry.id))?;
        let public_key_entry = protocol_types::PublicKeyEntry { id: key_entry.id.clone(),
                                                                                scheme: key_entry.key.get_scheme() as i32, 
                                                                                group: key_entry.key.get_group() as i32, 
                                                                                key: key_ser};
        Ok(public_key_entry)
    }
    // pub fn get_public_key_by_id(&self, id: &String) -> Result<protocol_types::PublicKeyEntry, String> {
    //     match self.get_key_by_id(id){
    //         Ok(priv_key_entry) => Ok(priv_key_entry.key.get_public_key()),
    //         Err(err) => Err(err),
    //     }
    // }

    // pub fn get_public_key_by_type(&self, scheme: ThresholdScheme, group: Group) -> Result<protocol_types::PublicKeyEntry, String> {
    //     match self.get_key_by_type(scheme, group){
    //         Ok(priv_key_entry) => Ok(priv_key_entry.key.get_public_key()),
    //         Err(err) => Err(err),
    //     }
    // }

}