use std::{env, process::exit, fs::File, io::Write};

use hex::FromHex;
use rand::rngs::OsRng;
use schemes::{keys::{KeyGenerator, PrivateKey, PublicKey}, interface::{Serializable, ThresholdCipher, ThresholdCipherParams, Ciphertext, ThresholdCryptoError, ThresholdSignature, Signature}, rand::{RNG, RngAlgorithm}, scheme_types_impl::SchemeDetails};
use protocols::keychain::KeyChain;
use thetacrypt_proto::scheme_types::{ThresholdScheme, Group};
use std::fs;

use clap::{Parser, ValueEnum, Subcommand, Args};

#[derive(Parser, Debug)]
#[command(version = "1.0", about, long_about = None)]
#[command(propagate_version = true)]
pub struct ThetaCliArgs {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    keygen(KeyGenArgs),
    enc(EncArgs),
    verify(VerifyArgs)
}

#[derive(Args, Debug)]
struct KeyGenArgs {
    #[arg(short, 
        help = "Threshold (minimum number of parties that need to collaborate)", 
    )]
    pub k: u16,
    #[arg(
        short,
        help = "Number of parties"
    )]
    pub n: u16,
    #[arg(
        short,
        long,
        help = "A list of comma separated elements of the format 'scheme-group', where 'scheme' is one of the following:\n\t encryption schemes: sg02, bz03\n\t signature schemes: bls04, frost, sh00\n\t coin schemes: cks05\nand 'group' is one of\n\t 'bls12381', 'bn254', 'ed25519', 'rsa512', 'rsa1024', 'rsa2048'.\nexample: sg02-bls12381,bz03-ed25519",
    )]
    pub subjects: String,
    #[arg(
        short,
        long,
        help = "Directory to store the generated keys in",
    )]
    pub dir: String,
}
#[derive(Args, Debug)]
struct EncArgs {
    #[arg(
        short, 
        long,
        help = "The path to the input file"
    )]
    pub infile: String,
    #[arg(
        short,
        long,
        help = "The path to the key file",
    )]
    pub key_path: String,
    #[arg(
        short,
        long,
        help = "The encryption label"
    )]
    pub label: String,
    #[arg(
        short,
        long,
        help = "The output path"
    )]
    pub outfile: String,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    #[arg(
        short,
        long,
        help = "The path to the public key file"
    )]
    pub key_path: String,
    #[arg(
        short,
        long,
        help = "The path to the file containing the message"
    )]
    pub message_path: String,
    #[arg(
        short,
        long,
        help = "The path to the file containing the signature",
    )]
    pub signature_path: String,
}


fn main() -> Result<(), ThresholdCryptoError> {
    let args = ThetaCliArgs::parse();

    if let Commands::keygen(keyGenArgs) = args.command {
        return keygen(keyGenArgs.k, keyGenArgs.n, &keyGenArgs.subjects, &keyGenArgs.dir);
    }

    if let Commands::enc(encArgs) = args.command {
        return encrypt(&encArgs.infile, encArgs.label.as_bytes(), &encArgs.outfile, &encArgs.key_path);  
    }

    if let Commands::verify(verifyArgs) = args.command {
        return verify(&verifyArgs.key_path, &verifyArgs.message_path, &verifyArgs.signature_path);
    }

    return Ok(());
}

fn keygen(k: u16, n: u16, a: &str, dir: &str) -> Result<(), ThresholdCryptoError> {
    let parts = a.split(',');
    let mut keys = Vec::new();
    let mut rng = RNG::new(RngAlgorithm::OsRng);

    if fs::create_dir_all(dir).is_err() {
        println!("Error: could not create directory");
        return Err(ThresholdCryptoError::IOError);
    }

    for part in parts {
        let mut s = part.split('-');

        let scheme_str = s.next();
        if scheme_str.is_none() {
            println!("Invalid format of argument 'subjects'");
            return Err(ThresholdCryptoError::InvalidParams);
        }

        let scheme = ThresholdScheme::parse_string(scheme_str.unwrap());
        if scheme.is_err() {
            println!("Invalid scheme '{}' selected", scheme_str.unwrap());
            return Err(ThresholdCryptoError::InvalidParams);
        }

        let group_str = s.next();
        if group_str.is_none() {
            println!("Invalid format of argument 'subjects'");
            return Err(ThresholdCryptoError::InvalidParams);
        }

        let group = Group::from_str_name(group_str.unwrap());
        if group.is_none() {
            println!("Invalid group '{}' selected", group_str.unwrap());
            return Err(ThresholdCryptoError::InvalidParams);
        }

        let mut name = String::from(group_str.unwrap());
        name.insert_str(0, "_");
        name.insert_str(0, scheme_str.unwrap());
        let key = KeyGenerator::generate_keys(k as usize, n as usize, &mut rng, &scheme.unwrap(), &group.unwrap(), &Option::None).expect("Failed to generate keys");

        let pubkey = key[0].get_public_key().serialize().unwrap();
        let file = File::create(format!("{}/{}.pub", dir, part));
        if let Err(e) = file.unwrap().write_all(&pubkey) {
            println!("Error storing public key: {}", e.to_string());
            return Err(ThresholdCryptoError::IOError);
        }

        keys.insert(0, (name, key));
    }

    for node_id in 0..n {
        let mut key_chain = KeyChain::new();
        for k in &keys {
            key_chain.insert_key(k.1[node_id as usize].clone(), k.0.clone()).expect("error generating key");
        }

        let keyfile = format!("{}/keys_{:?}.json", dir, node_id);
        key_chain.to_file(&keyfile).expect("error storing keys");
    }

    println!("Keys successfully generated.");
    return Ok(());
}

fn encrypt(infile: &str, label: &[u8], outfile: &str, key_path: &str) -> Result<(), ThresholdCryptoError> {
    let contents = fs::read(key_path);

    if let Err(e) = contents {
        println!("Error reading public key: {}", e.to_string());
        return Err(ThresholdCryptoError::DeserializationFailed);
    }

    let key = PublicKey::deserialize(&contents.unwrap());     

    if let Err(e) = key {
        println!("Error reading public key: {}", e.to_string());
        return Err(ThresholdCryptoError::DeserializationFailed);
    }   

    let key = key.unwrap();
    let msg = fs::read(infile);

    if let Err(e) = msg {
        println!("Error reading input file: {}", e.to_string());
        return Err(ThresholdCryptoError::DeserializationFailed);
    }

    let file = File::create(outfile);
    if let Err(e) = file {
         println!("Error creating output file: {}", e.to_string());
         return Err(ThresholdCryptoError::IOError);
    }

    let msg = msg.unwrap();

    let mut params = ThresholdCipherParams::new();
    let ct = ThresholdCipher::encrypt(&msg, label, &key, &mut params);

    if let Err(e) = ct {
        println!("Error encrypting message: {}", e.to_string());
        return Err(e);
    }

    let ct = ct.unwrap().serialize();
    
    if let Err(e) = ct {
        println!("Error serializing ciphertext: {}", e.to_string());
        return Err(e);
    }

    let ct = ct.unwrap();

    if let Err(e) = file.unwrap().write_all(&ct) {
        println!("Error storing ciphertext: {}", e.to_string());
        return Err(ThresholdCryptoError::IOError);
    }

    return Ok(());
}

fn verify(key_path: &str, message_path: &str, signature_path: &str) -> Result<(), ThresholdCryptoError> {
    let contents = fs::read(key_path);

    if let Err(e) = contents {
        println!("Error reading public key: {}", e.to_string());
        return Err(ThresholdCryptoError::DeserializationFailed);
    }

    let key = PublicKey::deserialize(&contents.unwrap());     

    if let Err(e) = key {
        println!("Error reading public key: {}", e.to_string());
        return Err(ThresholdCryptoError::DeserializationFailed);
    }   

    let key = key.unwrap();
    let msg = fs::read(message_path);

    if let Err(e) = msg {
        println!("Error reading mesage file: {}", e.to_string());
        return Err(ThresholdCryptoError::DeserializationFailed);
    }

    let hex_signature = fs::read_to_string(signature_path);

    if let Err(e) = hex_signature {
        println!("Error decoding hex encoded signature: {}", e.to_string());
        return Err(ThresholdCryptoError::DeserializationFailed);
    }


    let hex_signature = hex_signature.unwrap();

    println!("{}", &hex_signature);

    let signature = Vec::from_hex(hex_signature);

    if let Err(e) = signature {
        println!("Error decoding hex encoded signature: {}", e.to_string());
        return Err(ThresholdCryptoError::DeserializationFailed);
    }

    let signature = Signature::deserialize(&signature.unwrap());
    if let Err(e) = signature {
        println!("Error decoding hex encoded signature: {}", e.to_string());
        return Err(ThresholdCryptoError::DeserializationFailed);
    }

    if let Ok(b) = ThresholdSignature::verify(&signature.unwrap(), &key,& msg.unwrap()) {
        if b {
            println!("Signature valid");
            return Ok(());
        }
    }

    println!("Invalid signature");

    Err(ThresholdCryptoError::InvalidRound)
}