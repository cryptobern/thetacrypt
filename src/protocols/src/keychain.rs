use std::{collections::HashMap, fs::{self, File}, error::Error};
use cosmos_crypto::{keys::{PrivateKey, PublicKey}, interface::{Ciphertext, ThresholdScheme}, dl_schemes::dl_groups::dl_group::Group};
use serde::{Serialize, Deserialize, Serializer, ser::{SerializeSeq, SerializeStruct}};
use std::io::Write;

#[derive(Serialize, Deserialize)]
pub struct KeyChain {
    key_entries: Vec<KeyEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyEntry{
    pub id: String,
    is_default: bool,
    pub key: cosmos_crypto::keys::PrivateKey
}

impl KeyChain {
    
    pub fn new() -> Self {
        KeyChain {
            key_entries: Vec::new(),
        }
    }

    pub fn from_file(filename: &str) -> std::io::Result<Self> {
        let key_chain_str = fs::read_to_string(filename)?;
        let key_chain: KeyChain = serde_json::from_str(&key_chain_str)?; 
        Ok(key_chain)
    }

    pub fn to_file(&self, filename: &str) -> std::io::Result<()> {
        let serialized = serde_json::to_string(&self)?;
        let mut file = File::create(filename)?;
        writeln!(&mut file, "{}", serialized)?;
        Ok(())
    }

    // Inserts a key to the key_chain. A key_id must be given and must be unique among all keys (regardless of the key scheme).
    // A key is assumed default if it is the first key created for its scheme and group
    pub fn insert_key(&mut self, key: PrivateKey, key_id: String) -> Result<(), String> {
        if self.key_entries
                .iter()
                .any(|entry| entry.id == key_id) 
        {
            return Err(String::from("KEYC: A key wit key_id: already exists."));
        }
        let scheme = key.get_scheme();
        let group = key.get_group();
        let is_default = ! self.key_entries
                                  .iter()
                                  .any(|entry| entry.key.get_scheme() == scheme && entry.key.get_group() == group);
    
        self.key_entries.push(KeyEntry{ id: key_id, is_default, key });
        Ok(())
    }
 
    // Return the matching key with the given key_id, or an error if no key with key_id exists.
    pub fn get_key_by_id(&self, id: &String) -> Result<KeyEntry, String> {
        let key_entries_mathcing_id: Vec<&KeyEntry> = self.key_entries
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
    // Otherwise, return the defult key among the matching ones (there should be only one).
    pub fn get_key_by_type(&self, scheme: ThresholdScheme, group: Group) -> Result<KeyEntry, String> {
        let matching_key_entries: Vec<&KeyEntry> = self.key_entries
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
                let default_key_entries: Vec<&KeyEntry> = matching_key_entries
                                                        .iter()
                                                        .filter(|&entry| entry.is_default)
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

    // todo: Change these to return a KeyEntry for PublicKey
    pub fn get_public_key_by_id(&self, id: &String) -> Result<PublicKey, String> {
        match self.get_key_by_id(id){
            Ok(priv_key_entry) => Ok(priv_key_entry.key.get_public_key()),
            Err(err) => Err(err),
        }
    }

    pub fn get_public_key_by_type(&self, scheme: ThresholdScheme, group: Group) -> Result<PublicKey, String> {
        match self.get_key_by_type(scheme, group){
            Ok(priv_key_entry) => Ok(priv_key_entry.key.get_public_key()),
            Err(err) => Err(err),
        }
    }

}