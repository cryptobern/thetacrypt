use std::{env, process::exit, fs::{File, OpenOptions}, io::{Write, Read}, collections::HashMap};

use clap::Parser;
use hex::FromHex;
use rand::rngs::OsRng;
use theta_schemes::{keys::{KeyGenerator, PrivateKey, PublicKey}, interface::{Serializable, ThresholdCipher, ThresholdCipherParams, Ciphertext, ThresholdCryptoError, ThresholdSignature, Signature}, rand::{RNG, RngAlgorithm}, scheme_types_impl::{SchemeDetails, GroupDetails}, group::GroupData};
use theta_orchestration::keychain::KeyChain;
use theta_proto::scheme_types::{ThresholdScheme, Group};
use utils::{thetacli::cli::*, server::types::ProxyNode};
use std::fs;
use thiserror::Error;

#[derive(Debug, Error)]
enum Error {
    #[error("file error: {0}")]
    File(#[from] std::io::Error),
    #[error("download error: {0}")]
    Threshold(#[from] ThresholdCryptoError),
    #[error("download error: {0}")]
    Serde(#[from] serde_json::Error),
}

fn main() -> Result<(), Error> {
    let args = ThetaCliArgs::parse();

    if let Commands::keygen(keyGenArgs) = args.command {
        return keygen(keyGenArgs.k, keyGenArgs.n, &keyGenArgs.subjects, &keyGenArgs.dir, keyGenArgs.append);
    }

    if let Commands::enc(encArgs) = args.command {
        return encrypt(&encArgs.infile, encArgs.label.as_bytes(), &encArgs.outfile, &encArgs.key_path);  
    }

    if let Commands::verify(verifyArgs) = args.command {
        return verify(&verifyArgs.key_path, &verifyArgs.message_path, &verifyArgs.signature_path);
    }

    return Ok(());
}

fn keygen(k: u16, n: u16, a: &str, dir: &str, append: bool) -> Result<(), Error> {


    let mut parts = a.split(',');
    let mut keys = HashMap::new();
    let mut rng = RNG::new(RngAlgorithm::OsRng);

    if fs::create_dir_all(dir).is_err() {
        println!("Error: could not create directory");
        return Err(Error::Threshold(ThresholdCryptoError::IOError));
    }

    let mut default_key_set = generate_valid_scheme_group_pairs();
    for string in default_key_set.clone(){
        println!("{}", string)
    }
   

    if a == "default" {
        default_key_set = vec![default_key_set.join(",")];
        let str_list = default_key_set[0].as_str();
        println!("{}", str_list);
        parts = str_list.split(',');
    }

    for part in parts {
        let mut s = part.split('-');

        let scheme_str = s.next();
        if scheme_str.is_none() {
            println!("Invalid format of argument 'subjects'");
            return Err(Error::Threshold(ThresholdCryptoError::InvalidParams));
        }

        let scheme = ThresholdScheme::parse_string(scheme_str.unwrap());
        if scheme.is_err() {
            println!("Invalid scheme '{}' selected", scheme_str.unwrap());
            return Err(Error::Threshold(ThresholdCryptoError::InvalidParams));
        }

        let group_str = s.next();
        if group_str.is_none() {
            println!("Invalid format of argument 'subjects'");
            return Err(Error::Threshold(ThresholdCryptoError::InvalidParams));
        }

        // TODO: use the same method for parsing the string. For ThresholdScheme::parse_string (schemes_types_impl.rs), Group::from_str_name (schemes_types.rs)
        let group = Group::from_str_name(group_str.unwrap());
        if group.is_none() {
            println!("Invalid group '{}' selected", group_str.unwrap());
            return Err(Error::Threshold(ThresholdCryptoError::InvalidParams));
        }

        // Creation of the id (name) given to a certain key. For now the name is based on scheme_group info.
        // TODO: decide a way to create unique identifiers to have multiple keys of the same type. 
        let mut name = String::from(group_str.unwrap());
        name.insert_str(0, "_");
        name.insert_str(0, scheme_str.unwrap());

        let key = KeyGenerator::generate_keys(k as usize, n as usize, &mut rng, &scheme.unwrap(), &group.unwrap(), &Option::None).expect("Failed to generate keys");

        // Extraction of the public key and creation of a .pub file
        let pubkey = key[0].get_public_key().serialize().unwrap();
        let file = File::create(format!("{}/{}.pub", dir, part));
        if let Err(e) = file.unwrap().write_all(&pubkey) {
            println!("Error storing public key: {}", e.to_string());
            return Err(Error::Threshold(ThresholdCryptoError::IOError));
        }

        keys.insert(name.clone(),key);
    }

    for node_id in 0..n {

        // Define the expected internal structure of the dictionary of keys 
        // TODO: this can be a defined struct
        let mut node_keys: HashMap<String, PrivateKey> = HashMap::new();

        // Define the name of the key file based on the node 
        let keyfile = format!("{}/keys_{:?}.json", dir, node_id);

        if append {

            // Open the file, or create it before opening
            let mut file = File::options().write(true).read(true).create(true).open(keyfile.clone())?;

            // Read if there are already key in it. If the file has just been created the file will simply be empty
            let mut data = String::new();
            file.read_to_string(&mut data)?;

            // Check if there was something already written, read in order to append, and write again.
            // Not optimal, but this is just a set up phase. 
            if !data.is_empty(){
                node_keys = serde_json::from_str(&mut data)?
            }
        }
        
        // each value in keys is a vector of secret key share (related to the same pk) that needs to be distributed among the right key file (parties)
        for k in keys.clone() {
            // the node_id refers to the index of a specific party and it is used to index the right share for the party
            node_keys.insert(k.0.clone(), k.1[node_id as usize].clone());
        }

        // Here the information about the keys of a specific party are actually being written on file
        // TODO: eventually here there could be a protocol for an online phase to send the information to the Thetacrypt instances. 
        let write_file = File::create(&keyfile)?;
        serde_json::to_writer(write_file, &node_keys)?;
    }

    println!("Keys successfully generated.");
    return Ok(());
}

fn encrypt(infile: &str, label: &[u8], outfile: &str, key_path: &str) -> Result<(), Error> {
    let contents = fs::read(key_path);

    if let Err(e) = contents {
        println!("Error reading public key: {}", e.to_string());
        return Err(Error::Threshold(ThresholdCryptoError::DeserializationFailed));
    }

    let key = PublicKey::deserialize(&contents.unwrap());     

    if let Err(e) = key {
        println!("Error reading public key: {}", e.to_string());
        return Err(Error::Threshold(ThresholdCryptoError::DeserializationFailed));
    }   

    let key = key.unwrap();
    let msg = fs::read(infile);

    if let Err(e) = msg {
        println!("Error reading input file: {}", e.to_string());
        return Err(Error::Threshold(ThresholdCryptoError::DeserializationFailed));
    }

    let file = File::create(outfile);
    if let Err(e) = file {
         println!("Error creating output file: {}", e.to_string());
         return Err(Error::Threshold(ThresholdCryptoError::IOError));
    }

    let msg = msg.unwrap();

    let mut params = ThresholdCipherParams::new();
    let ct = ThresholdCipher::encrypt(&msg, label, &key, &mut params);

    if let Err(e) = ct {
        println!("Error encrypting message: {}", e.to_string());
        return Err(Error::Threshold(e));
    }

    let ct = ct.unwrap().serialize();
    
    if let Err(e) = ct {
        println!("Error serializing ciphertext: {}", e.to_string());
        return Err(Error::Threshold(e));
    }

    let ct = ct.unwrap();

    if let Err(e) = file.unwrap().write_all(&ct) {
        println!("Error storing ciphertext: {}", e.to_string());
        return Err(Error::Threshold(ThresholdCryptoError::IOError));
    }

    return Ok(());
}

fn verify(key_path: &str, message_path: &str, signature_path: &str) -> Result<(), Error> {
    let contents = fs::read(key_path);

    if let Err(e) = contents {
        println!("Error reading public key: {}", e.to_string());
        return Err(Error::Threshold(ThresholdCryptoError::DeserializationFailed));
    }

    let key = PublicKey::deserialize(&contents.unwrap());     

    if let Err(e) = key {
        println!("Error reading public key: {}", e.to_string());
        return Err(Error::Threshold(ThresholdCryptoError::DeserializationFailed));
    }   

    let key = key.unwrap();
    let msg = fs::read(message_path);

    if let Err(e) = msg {
        println!("Error reading mesage file: {}", e.to_string());
        return Err(Error::Threshold(ThresholdCryptoError::DeserializationFailed));
    }

    let hex_signature = fs::read_to_string(signature_path);

    if let Err(e) = hex_signature {
        println!("Error decoding hex encoded signature: {}", e.to_string());
        return Err(Error::Threshold(ThresholdCryptoError::DeserializationFailed));
    }


    let hex_signature = hex_signature.unwrap();

    println!("{}", &hex_signature);

    let signature = Vec::from_hex(hex_signature);

    if let Err(e) = signature {
        println!("Error decoding hex encoded signature: {}", e.to_string());
        return Err(Error::Threshold(ThresholdCryptoError::DeserializationFailed));
    }

    let signature = Signature::deserialize(&signature.unwrap());
    if let Err(e) = signature {
        println!("Error decoding hex encoded signature: {}", e.to_string());
        return Err(Error::Threshold(ThresholdCryptoError::DeserializationFailed));
    }

    if let Ok(b) = ThresholdSignature::verify(&signature.unwrap(), &key,& msg.unwrap()) {
        if b {
            println!("Signature valid");
            return Ok(());
        }
    }

    println!("Invalid signature");

    Err(Error::Threshold(ThresholdCryptoError::InvalidRound))
}


fn generate_valid_scheme_group_pairs() -> Vec<String> {
    let mut scheme_group_vec: Vec<String> = Vec::new();
    let mut i: i32 = 0;
    loop {
        
        let scheme = match ThresholdScheme::from_i32(i) {
            Some(scheme) => scheme,
            None => break,
        };

        let mut j:i32 = 0;
        loop {
            let group = match Group::from_i32(j) {
                Some(group) => group,
                None => break,
            };

            //check conditions for a specific scheme
            if scheme.check_valid_group(group) {
                let mut new_scheme_group = String::from(group.as_str_name());
                new_scheme_group.insert_str(0, "-");
                new_scheme_group.insert_str(0, scheme.as_str_name());

                //update the list
                scheme_group_vec.push(new_scheme_group);                
            }

            j += 1;
        }

        i +=1;

    }
    return scheme_group_vec
}