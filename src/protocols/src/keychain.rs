use std::{collections::HashMap, fs::{self, File}, error::Error};
use cosmos_crypto::{keygen::{PrivateKey, ThresholdScheme}, interface::Ciphertext};
use serde::{Serialize, Deserialize, Serializer, ser::{SerializeSeq, SerializeStruct}};
use std::io::Write;
// use serde_with::serde_as;
    
// Each (crate::pb::requests::ThresholdCipher, crate::pb::requests::DlGroup) pair maps to HashMap of (possibly more than one) key entries.
// Each key entry is a key-pair map from a key-id (string) to the actual key content (Vec<u8>).
// Keys in the KeyChain are store in a serialized form.
// #[serde_as]
// #[derive(Serialize, Deserialize, Debug)]
// pub struct KeyChain {
//     #[serde_as(as = "Vec<(_, _)>")]
//     key_chain: HashMap<(crate::pb::requests::ThresholdCipher, crate::pb::requests::DlGroup), HashMap<String, Vec<u8>>>
// }

pub struct KeyEntry{
    id: String,
    scheme: cosmos_crypto::keygen::ThresholdScheme, // todo: I think the group is included in the scheme enum, right?
    is_default: bool,
    key: cosmos_crypto::keygen::PrivateKey
}

#[derive(Serialize)]
pub struct KeyEntryInternal<'a>{
    id: &'a str,
    is_default: bool,
    key: &'a cosmos_crypto::keygen::PrivateKey
}

// impl Serialize for KeyEntry {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer
//     {
//         let mut state = serializer.serialize_struct("KeyEntry", 4)?;
//         state.serialize_field("id", &self.id)
//         seq.end()
//     }
// }


// impl Serialize for KeyChain {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer
//     {
//         let mut seq = serializer.serialize_seq(Some(self.key_entries.len()))?;
//         for e in self.key_entries {
//             seq.serialize_element(e)?;
//         }
//         seq.end()
//     }
// }


pub struct KeyChain {
    key_entries: Vec<KeyEntry>,
}

impl KeyChain{
    
    // pub fn from_file(filename: &str) -> Self {
    //     let key_chain_str = fs::read_to_string(filename).unwrap();
    //     let key_chain_internal: Vec<KeyEntryInternal> = serde_json::from_str(&key_chain_str).unwrap();

    // }

    pub fn to_file(&self, filename: &str){
        let key_chain_internal: Vec<KeyEntryInternal> = self.key_entries
                                                    .iter()
                                                    .map(|e| KeyEntryInternal{ id: &e.id, is_default: e.is_default, key: &e.key })
                                                    .collect();
        let serialized = serde_json::to_string(&key_chain_internal).unwrap();
        let mut file = File::create(filename).unwrap();
        writeln!(&mut file, "{}", serialized).unwrap();
    }

    pub fn new() -> Self {
        KeyChain {
            key_entries: Vec::new(),
        }
    }

    // Inserts a key to the key_chain. A key_id must be given and must be unique among all keys (regardless of the key scheme).
    // A key is assumed default if it is the first key created for its scheme
    pub fn insert_key(&mut self, key: PrivateKey, key_id: String) -> Result<(), String> {
        if self.key_entries
                .iter()
                .any(|entry| entry.id == key_id) 
        {
            return Err(String::from("KEYC: A key wit key_id: already exists."));
        }
        let scheme = key.get_scheme();
        let is_default = ! self.key_entries
                                  .iter()
                                  .any(|entry| entry.scheme == scheme);
    
        self.key_entries.push(KeyEntry{ id: key_id, scheme, key, is_default });
        Ok(())
    }
 
    
    // pub fn get_key(&self, scheme: crate::pb::requests::ThresholdCipher, domain: crate::pb::requests::DlGroup, key_id: Option<String>) -> Result<Vec<u8>, String>{
    //     match self.key_chain.get(&(scheme, domain)){
    //         Some(matching_keys) => {
    //             match matching_keys.len() {
    //                0 => { 
    //                    Err(String::from("No keys found for the requested scheme and domain.")) 
    //                 },
    //                1 => {
    //                     Ok(matching_keys.values().next().unwrap().clone())
    //                },
    //                 _ => {
    //                     match key_id {
    //                         Some(id) => {
    //                             match matching_keys.get(&id) {
    //                                 Some(key) => { 
    //                                     Ok(key.clone()) 
    //                                 },
    //                                 None => {
    //                                     Err(String::from("No keys found for the requested key_id."))
    //                                 },
    //                             }
    //                         },
    //                         None => {
    //                             Err(String::from("Multiple keys exist. Please requested key_id."))
    //                         }
    //                     }
    //                 }
    //             }
    //         },
    //         None => {
    //             Err(String::from("No keys found for the requested scheme and domain."))
    //         },
    //     }
    // }

    // Current logic: First filter all keys and keep those that match the given scheme.
    // If there is no matching key, return an error.
    // Otherwise, key_id has priority over the default key: 
    // - if the a key_id is specified, return the matching key with that key_id, or an error if no key with key_id exists.
    // - if no key_id was specified, return the defult key among the matching ones (there should be only one).
    pub fn get_key(&self, scheme: ThresholdScheme, key_id: Option<String>) -> Result<PrivateKey, String> {
        let matching_key_entries: Vec<&KeyEntry> = self.key_entries
            .iter()
            .filter(|&entry| entry.scheme == scheme)
            .collect();
        return match matching_key_entries.len(){
            0 => {
                Err(String::from("No key matches the required scheme."))
            },
            _ => {
                match key_id {
                    Some(id) => {
                        let key_entries_with_id: Vec<&KeyEntry> = matching_key_entries
                                                                .iter()
                                                                .filter(|&entry| entry.id == id)
                                                                .map(|e| *e)
                                                                .collect();
                        match key_entries_with_id.len(){
                            0 => {
                                Err(String::from("Could not find a key with the given key_id: {key_id}."))
                            },
                            1 => {
                                Ok(key_entries_with_id.get(0).unwrap().key.clone())
                            },
                            _ => {
                                print!(">> KEYC: ERROR: More than one keys with the same id were found. key_id: {id}.");
                                Err(String::from("More than one keys with key_id: {key_id} were found."))
                            }
                        }
                    },
                    None => {
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
                                Ok(default_key_entries.get(0).unwrap().key.clone())
                            },
                            _ => {
                                print!(">> KEYC: ERROR: No more thatn one key should always be specified as default.");
                                Err(String::from("Could not select a default key for this scheme. Please specify a key id."))
                            }
                        
                        }   
                    }
                }
            }
        }

    }
}