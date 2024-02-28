use std::{
    collections::HashMap,
    fmt::Debug,
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use clap::Parser;
use hex::FromHex;
use terminal_menu::{button, label, menu, mut_menu, run, TerminalMenuItem};

use std::fs;
use theta_proto::{
    protocol_types::{threshold_crypto_library_client::ThresholdCryptoLibraryClient, KeyRequest},
    scheme_types::{Group, ThresholdOperation, ThresholdScheme},
};
use theta_schemes::{
    interface::{
        SchemeError, Serializable, Signature, ThresholdCipher, ThresholdCipherParams,
        ThresholdSignature,
    },
    keys::{
        key_generator::KeyGenerator,
        key_store::KeyStore,
        keys::{PrivateKeyShare, PublicKey},
    },
    rand::{RngAlgorithm, RNG},
    scheme_types_impl::SchemeDetails,
};
use thiserror::Error;
use utils::thetacli::cli::*;

#[derive(Error)]
enum Error {
    #[error("file error: {0}")]
    File(#[from] std::io::Error),
    #[error("threshold error: {0}")]
    Threshold(#[from] SchemeError),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("error: {0}")]
    String(String),
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(arg0) => f.debug_tuple("File").field(arg0).finish(),
            Self::Threshold(arg0) => f.debug_tuple("Threshold").field(arg0).finish(),
            Self::Serde(arg0) => f.debug_tuple("Serde").field(arg0).finish(),
            Self::String(arg0) => f.write_str(&arg0),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = ThetaCliArgs::parse();

    match args.command {
        Commands::Keygen(key_gen_args) => {
            return keygen(
                key_gen_args.k,
                key_gen_args.n,
                &key_gen_args.subjects,
                &key_gen_args.output,
                key_gen_args.new,
            );
        }
        Commands::Enc(enc_args) => {
            return encrypt(
                &enc_args.infile,
                enc_args.label.as_bytes(),
                &enc_args.output,
                enc_args.pubkey,
                enc_args.keystore,
                enc_args.key_id,
            );
        }
        Commands::Verify(verify_args) => {
            return verify(
                &verify_args.message_path,
                &verify_args.signature_path,
                verify_args.pubkey,
                verify_args.keystore,
                verify_args.key_id,
            );
        }
        Commands::Keystore(keystore_args) => {
            return keystore(
                &keystore_args.action,
                &keystore_args.keystore,
                keystore_args.address,
                keystore_args.new,
                keystore_args.input,
            )
            .await;
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

    if new {
        let _ = fs::remove_dir_all(dir.to_owned() + "/pub");
    }

    if fs::create_dir_all(dir.to_owned() + "/pub/").is_err() {
        println!("Error: could not create directory");
        return Err(Error::Threshold(SchemeError::IOError));
    }

    let mut default_key_set: Vec<String>;

    println!("Generating keys...");

    if a == "all" {
        default_key_set = generate_valid_scheme_group_pairs();
        default_key_set = vec![default_key_set.join(",")];
        let str_list = default_key_set[0].as_str();
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

        println!("Generating {}...", part);

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

        // Extraction of the public key and creation of a .pub file
        let pubkey = key[0].get_public_key().to_bytes().unwrap();
        let file = File::create(format!("{}/pub/{}_{}.pub", dir, part, key[0].get_key_id()));
        if let Err(e) = file.unwrap().write_all(&pubkey) {
            println!("Error storing public key: {}", e.to_string());
            return Err(Error::Threshold(SchemeError::IOError));
        }

        keys.insert(name.clone(), key);
    }

    for node_id in 0..n {
        // Define the name of the key file based on the node
        let keyfile = format!("{}/node{:?}.keystore", dir, node_id);
        let mut kc = KeyStore::new();

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

        println!("Created {}", keyfile);
    }

    println!("Keys successfully generated.");
    return Ok(());
}

fn encrypt(
    infile: &Option<String>,
    label: &[u8],
    outfile: &str,
    key_path: Option<String>,
    keystore_path: Option<String>,
    key_id: Option<String>,
) -> Result<(), Error> {
    let key = load_key(
        key_path,
        keystore_path,
        key_id,
        ThresholdOperation::Encryption,
    );
    if key.is_err() {
        return Err(key.unwrap_err());
    }
    let key = key.unwrap();

    let msg;

    if infile.is_none() {
        let mut stdin = std::io::stdin();
        let mut buf = Vec::new();

        if atty::isnt(atty::Stream::Stdin) {
            let _ = stdin.read_to_end(&mut buf);
        }

        if buf.is_empty() {
            return Err(Error::String(String::from("No message specified")));
        }

        msg = buf.to_vec();
    } else {
        let infile = infile.clone().unwrap();
        let tmp = fs::read(infile);

        if let Err(e) = tmp {
            println!("Error reading input file: {}", e.to_string());
            return Err(Error::Threshold(SchemeError::DeserializationFailed));
        }

        msg = tmp.unwrap();
    }

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

    if outfile == "-" {
        if std::io::stdout().write(&ct).is_err() {
            return Err(Error::Threshold(SchemeError::IOError));
        }
    } else {
        let file = File::create(outfile);
        if let Err(e) = file {
            println!("Error creating output file: {}", e.to_string());
            return Err(Error::Threshold(SchemeError::IOError));
        }

        if let Err(e) = file.unwrap().write_all(&ct) {
            println!("Error storing ciphertext: {}", e.to_string());
            return Err(Error::Threshold(SchemeError::IOError));
        }
    }

    return Ok(());
}

fn verify(
    message_path: &str,
    signature_path: &str,
    key_path: Option<String>,
    keystore_path: Option<String>,
    key_id: Option<String>,
) -> Result<(), Error> {
    let key = load_key(
        key_path,
        keystore_path,
        key_id,
        ThresholdOperation::Signature,
    );
    if key.is_err() {
        return Err(key.unwrap_err());
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

fn load_key(
    key_path: Option<String>,
    keystore_path: Option<String>,
    key_id: Option<String>,
    operation: ThresholdOperation,
) -> Result<PublicKey, Error> {
    let key;

    if key_path.is_some() {
        let contents = fs::read(key_path.unwrap());

        if let Err(e) = contents {
            println!("Error reading public key: {}", e.to_string());
            return Err(Error::Threshold(SchemeError::DeserializationFailed));
        }

        let tmp = PublicKey::from_bytes(&contents.unwrap());

        if let Err(e) = tmp {
            println!("Error reading public key: {}", e.to_string());
            return Err(Error::Threshold(SchemeError::DeserializationFailed));
        }

        key = tmp.unwrap();
    } else if keystore_path.is_some() {
        let keystore = KeyStore::from_file(&PathBuf::from(keystore_path.unwrap()));

        if keystore.is_err() {}

        let keystore = keystore.unwrap();

        if key_id.is_none() {
            let entries;

            match operation {
                ThresholdOperation::Coin => {
                    entries = keystore.get_coin_keys();
                }
                ThresholdOperation::Encryption => {
                    entries = keystore.get_encryption_keys();
                }
                ThresholdOperation::Signature => {
                    entries = keystore.get_signing_keys();
                }
            }

            let mut key_menu_items: Vec<TerminalMenuItem> =
                entries.iter().map(|x| button(x.to_string())).collect();
            key_menu_items.insert(0, label("Select Key:"));
            let key_menu = menu(key_menu_items);

            run(&key_menu);
            {
                let km = mut_menu(&key_menu);
                let tmp = entries
                    .iter()
                    .find(|k| km.selected_item_name().contains(&k.id));

                if tmp.is_none() {
                    println!("Error importing key");
                    return Err(Error::String(String::from("Error loading public key")));
                }

                key = tmp.unwrap().pk.clone();
            }
        } else {
            let tmp = keystore.get_key_by_id(&key_id.unwrap());

            if let Err(e) = tmp {
                println!("Error loading public key: {}", e.to_string());
                return Err(Error::Threshold(SchemeError::DeserializationFailed));
            }

            key = tmp.unwrap().pk;
        }
    } else {
        println!("Either pubkey or keystore need to be specified");
        return Err(Error::String(String::from(
            "Either pubkey or keystore need to be specified",
        )));
    }

    return Ok(key);
}

async fn keystore(
    action: &str,
    keystore_path: &str,
    address: Option<String>,
    new: bool,
    input: Option<String>,
) -> Result<(), Error> {
    match action {
        "ls" => {
            let tmp = KeyStore::from_file(&PathBuf::from(keystore_path));

            if tmp.is_err() {
                println!("Error reading key store!");
                return Err(Error::String(format!("Error reading key store!")));
            }

            let keystore = tmp.unwrap();

            println!("{}", keystore.to_string());
        }
        "fetch" => {
            if address.is_none() {
                println!("No node address specified");
                return Err(Error::String(String::from("No node address specified")));
            }

            let mut keystore;

            if !new {
                let tmp = KeyStore::from_file(&PathBuf::from(keystore_path));

                if tmp.is_err() {
                    println!("Error reading key store!");
                    return Err(Error::String(format!("Error reading key store!")));
                }

                keystore = tmp.unwrap();
            } else {
                keystore = KeyStore::new();
            }

            let address = address.unwrap();
            let connection = ThresholdCryptoLibraryClient::connect(address.clone()).await;
            if connection.is_err() {
                return Err(Error::String(format!("Could not connect to {}", address)));
            }

            let response = connection.unwrap().get_public_keys(KeyRequest {}).await;

            if response.is_err() {
                println!("Error fetching public keys!");
                return Err(Error::String(format!("Error fetching public keys!")));
            }

            let response = response.unwrap();
            let keys = &response.get_ref().keys;
            if let Err(e) = keystore.import_public_keys(keys) {
                return Err(Error::String(e));
            }

            if keystore.to_file(keystore_path).is_err() {
                println!("Error storing keys to keychain");
                return Err(Error::String(format!("Error storing keys to keychain")));
            }

            println!("Successfully imported keys from server");
        }
        "add" => {
            if input.is_none() {
                return Err(Error::String(String::from("No input key file provided")));
            }

            let key_file = fs::read(input.unwrap());

            if key_file.is_err() {
                return Err(Error::String(String::from("Error reading input key file")));
            }

            let tmp = KeyStore::from_file(&PathBuf::from(keystore_path));

            if tmp.is_err() {
                println!("Error reading key store!");
                return Err(Error::String(format!("Error reading key store!")));
            }

            let mut keystore = tmp.unwrap();
            let bytes = key_file.unwrap();

            let pk = PublicKey::from_bytes(&bytes);
            let mut key_type = "public";

            if pk.is_err() {
                let sk = PrivateKeyShare::from_bytes(&bytes);
                if sk.is_err() {
                    return Err(Error::String(String::from("Invalid key file")));
                }

                if let Err(e) = keystore.insert_private_key(sk.unwrap()) {
                    return Err(Error::String(e.to_string()));
                }

                key_type = "secret";
            } else {
                if let Err(e) = keystore.insert_public_key(pk.unwrap()) {
                    return Err(Error::String(e.to_string()));
                }
            }

            if let Err(e) = keystore.to_file(keystore_path) {
                return Err(Error::String(e.to_string()));
            }

            println!("Successfully added {} key to keystore", key_type);
        }
        _ => {
            println!("Invalid action. Valid actions are: ls, add, fetch");
        }
    }

    Ok(())
}
