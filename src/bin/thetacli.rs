use std::{collections::HashMap, fs::File, io::Write, path::PathBuf};

use clap::Parser;
use hex::FromHex;

use std::fs;
use theta_proto::scheme_types::{Group, ThresholdScheme};
use theta_schemes::{
    interface::{
        SchemeError, Serializable, Signature, ThresholdCipher, ThresholdCipherParams,
        ThresholdSignature,
    },
    keys::{key_chain::KeyChain, key_generator::KeyGenerator, keys::PublicKey},
    rand::{RngAlgorithm, RNG},
    scheme_types_impl::SchemeDetails,
};
use thiserror::Error;
use utils::thetacli::cli::*;

#[derive(Debug, Error)]
enum Error {
    #[error("file error: {0}")]
    File(#[from] std::io::Error),
    #[error("download error: {0}")]
    Threshold(#[from] SchemeError),
    #[error("download error: {0}")]
    Serde(#[from] serde_json::Error),
}

fn main() -> Result<(), Error> {
    let args = ThetaCliArgs::parse();

    match args.command {
        Commands::Keygen(key_gen_args) => {
            return keygen(
                key_gen_args.k,
                key_gen_args.n,
                &key_gen_args.subjects,
                &key_gen_args.dir,
                key_gen_args.new,
            );
        }
        Commands::Enc(enc_args) => {
            return encrypt(
                &enc_args.infile,
                enc_args.label.as_bytes(),
                &enc_args.outfile,
                &enc_args.key_path,
            );
        }
        Commands::Verify(verify_args) => {
            return verify(
                &verify_args.key_path,
                &verify_args.message_path,
                &verify_args.signature_path,
            );
        }
    }
}

fn keygen(k: u16, n: u16, a: &str, dir: &str, new: bool) -> Result<(), Error> {
    let mut parts = a.split(',');
    let mut keys = HashMap::new();
    let mut rng = RNG::new(RngAlgorithm::OsRng);

    if fs::create_dir_all(dir).is_err() {
        println!("Error: could not create directory");
        return Err(Error::Threshold(SchemeError::IOError));
    }

    let mut default_key_set: Vec<String>;

    if a == "all" {
        default_key_set = generate_valid_scheme_group_pairs();
        for string in default_key_set.clone() {
            println!("{}", string)
        }
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
            return Err(Error::Threshold(SchemeError::InvalidParams));
        }

        let scheme = ThresholdScheme::from_str_name(scheme_str.unwrap());
        if scheme.is_none() {
            println!("Invalid scheme '{}' selected", scheme_str.unwrap());
            return Err(Error::Threshold(SchemeError::InvalidParams));
        }

        let group_str = s.next();
        if group_str.is_none() {
            println!("Invalid format of argument 'subjects'");
            return Err(Error::Threshold(SchemeError::InvalidParams));
        }

        let group = Group::from_str_name(group_str.unwrap());
        if group.is_none() {
            println!("Invalid group '{}' selected", group_str.unwrap());
            return Err(Error::Threshold(SchemeError::InvalidParams));
        }

        // Creation of the id (name) given to a certain key. For now the name is based on scheme_group info.
        let mut name = String::from(group_str.unwrap());
        name.insert_str(0, "-");
        name.insert_str(0, scheme_str.unwrap());

        let key = KeyGenerator::generate_keys(
            k as usize,
            n as usize,
            &mut rng,
            &scheme.unwrap(),
            &group.unwrap(),
            &Option::None,
        )
        .expect("Failed to generate keys");

        keys.insert(name.clone(), key);
    }

    for node_id in 0..n {
        // Define the name of the key file based on the node
        let keyfile = format!("{}/keys_{:?}.json", dir, node_id);
        let mut kc = KeyChain::new();

        if !new {
            let _ = kc.load(&PathBuf::from(keyfile.clone()));
        }

        // each value in keys is a vector of secret key share (related to the same pk) that needs to be distributed among the right key file (parties)
        for k in keys.clone() {
            let _ = kc.insert_private_key(k.1[node_id as usize].clone());
        }

        // Here the information about the keys of a specific party are actually being written on file
        // TODO: eventually here there could be a protocol for an online phase to send the information to the Thetacrypt instances.
        let _ = kc.to_file(&keyfile);
    }

    println!("Keys successfully generated.");
    return Ok(());
}

fn encrypt(infile: &str, label: &[u8], outfile: &str, key_path: &str) -> Result<(), Error> {
    let contents = fs::read(key_path);

    if let Err(e) = contents {
        println!("Error reading public key: {}", e.to_string());
        return Err(Error::Threshold(SchemeError::DeserializationFailed));
    }

    let key = PublicKey::from_bytes(&contents.unwrap());

    if let Err(e) = key {
        println!("Error reading public key: {}", e.to_string());
        return Err(Error::Threshold(SchemeError::DeserializationFailed));
    }

    let key = key.unwrap();
    let msg = fs::read(infile);

    if let Err(e) = msg {
        println!("Error reading input file: {}", e.to_string());
        return Err(Error::Threshold(SchemeError::DeserializationFailed));
    }

    let file = File::create(outfile);
    if let Err(e) = file {
        println!("Error creating output file: {}", e.to_string());
        return Err(Error::Threshold(SchemeError::IOError));
    }

    let msg = msg.unwrap();

    let mut params = ThresholdCipherParams::new();
    let ct = ThresholdCipher::encrypt(&msg, label, &key, &mut params);

    if let Err(e) = ct {
        println!("Error encrypting message: {}", e.to_string());
        return Err(Error::Threshold(e));
    }

    let ct = ct.unwrap().to_bytes();

    if let Err(e) = ct {
        println!("Error serializing ciphertext: {}", e.to_string());
        return Err(Error::Threshold(e));
    }

    let ct = ct.unwrap();

    if let Err(e) = file.unwrap().write_all(&ct) {
        println!("Error storing ciphertext: {}", e.to_string());
        return Err(Error::Threshold(SchemeError::IOError));
    }

    return Ok(());
}

fn verify(key_path: &str, message_path: &str, signature_path: &str) -> Result<(), Error> {
    let contents = fs::read(key_path);

    if let Err(e) = contents {
        println!("Error reading public key: {}", e.to_string());
        return Err(Error::Threshold(SchemeError::DeserializationFailed));
    }

    let key = PublicKey::from_bytes(&contents.unwrap());

    if let Err(e) = key {
        println!("Error reading public key: {}", e.to_string());
        return Err(Error::Threshold(SchemeError::DeserializationFailed));
    }

    let key = key.unwrap();
    let msg = fs::read(message_path);

    if let Err(e) = msg {
        println!("Error reading mesage file: {}", e.to_string());
        return Err(Error::Threshold(SchemeError::DeserializationFailed));
    }

    let hex_signature = fs::read_to_string(signature_path);

    if let Err(e) = hex_signature {
        println!("Error decoding hex encoded signature: {}", e.to_string());
        return Err(Error::Threshold(SchemeError::DeserializationFailed));
    }

    let hex_signature = hex_signature.unwrap();

    println!("{}", &hex_signature);

    let signature = Vec::from_hex(hex_signature);

    if let Err(e) = signature {
        println!("Error decoding hex encoded signature: {}", e.to_string());
        return Err(Error::Threshold(SchemeError::DeserializationFailed));
    }

    let signature = Signature::from_bytes(&signature.unwrap());
    if let Err(e) = signature {
        println!("Error decoding hex encoded signature: {}", e.to_string());
        return Err(Error::Threshold(SchemeError::DeserializationFailed));
    }

    if let Ok(b) = ThresholdSignature::verify(&signature.unwrap(), &key, &msg.unwrap()) {
        if b {
            println!("Signature valid");
            return Ok(());
        }
    }

    println!("Invalid signature");

    Err(Error::Threshold(SchemeError::InvalidRound))
}

fn generate_valid_scheme_group_pairs() -> Vec<String> {
    let mut scheme_group_vec: Vec<String> = Vec::new();
    let mut i: i32 = 0;
    loop {
        let scheme = match ThresholdScheme::from_i32(i) {
            Some(scheme) => scheme,
            None => break,
        };

        let mut j: i32 = 0;

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

        i += 1;
    }
    return scheme_group_vec;
}
