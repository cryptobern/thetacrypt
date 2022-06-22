use std::{collections::HashMap, fs};
use serde::{Serialize, Deserialize, Serializer};
use serde_with::serde_as;
    
// Each (crate::pb::requests::ThresholdCipher, crate::pb::requests::DlGroup) pair maps to HashMap of (possibly more than one) key entries.
// Each key entry is a key-pair map from a key-id (string) to the actual key content (Vec<u8>).
// Keys in the KeyChain are store in a serialized form.
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyChain {
    #[serde_as(as = "Vec<(_, _)>")]
    key_chain: HashMap<(crate::pb::requests::ThresholdCipher, crate::pb::requests::DlGroup), HashMap<String, Vec<u8>>>
}

impl KeyChain{
    // todo: When the new version of deseralize (that returns the key wrapped in an enum) is ready, update this function.
    pub fn from_file(filename: &str) -> Self {
        let key_chain_str = fs::read_to_string(filename).unwrap();
        serde_json::from_str(&key_chain_str).unwrap()
    }

    pub fn new() -> Self {
        KeyChain {
            key_chain: HashMap::new(),
        }
    }

    // Inserts a key to the key_chain. A key_id must be given here.
    // Keys are stored in serialized form in the key_chain.
    pub fn insert_key(&mut self, scheme: crate::pb::requests::ThresholdCipher, domain: crate::pb::requests::DlGroup, key_id: String, key: Vec<u8>){
        if !self.key_chain.contains_key(&(scheme, domain)){
            self.key_chain.insert((scheme, domain), HashMap::new());
        }
        self.key_chain.get_mut(&(scheme, domain)).unwrap().insert(key_id, key);
    }
 
    // Current logic: We return the key (if any, otherwise error) defined for the given combination (scheme, domain).
    // If there are more than one, then we return the one with identifier key_id (if any, otherwise error).
    // In other words, we use the parameter key_id only in case more than one keys could match the given (scheme, domain).
    // todo: Probably better to refactor this into two functions, one with (scheme, domain) parameters and one with the key_id parameter..
    pub fn get_key(&self, scheme: crate::pb::requests::ThresholdCipher, domain: crate::pb::requests::DlGroup, key_id: Option<String>) -> Result<Vec<u8>, String>{
        match self.key_chain.get(&(scheme, domain)){
            Some(matching_keys) => {
                match matching_keys.len() {
                   0 => { 
                       Err(String::from("No keys found for the requested scheme and domain.")) 
                    },
                   1 => {
                        Ok(matching_keys.values().next().unwrap().clone())
                   },
                    _ => {
                        match key_id {
                            Some(id) => {
                                match matching_keys.get(&id) {
                                    Some(key) => { 
                                        Ok(key.clone()) 
                                    },
                                    None => {
                                        Err(String::from("No keys found for the requested key_id."))
                                    },
                                }
                            },
                            None => {
                                Err(String::from("Multiple keys exist. Please requested key_id."))
                            }
                        }
                    }
                }
            },
            None => {
                Err(String::from("No keys found for the requested scheme and domain."))
            },
        }
    }
}