use std::{env, process::exit, fs::File, io::Write};

use hex::FromHex;
use rand::rngs::OsRng;
use schemes::{keys::{KeyGenerator, PrivateKey, PublicKey}, interface::{ThresholdScheme, Serializable, ThresholdCipher, ThresholdCipherParams, Ciphertext, ThresholdCryptoError, ThresholdSignature, Signature}, group::Group, rand::{RNG, RngAlgorithm}};
use protocols::keychain::KeyChain;
use std::fs;

fn main() -> Result<(), ()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        print_info();
        return Err(());
    }

    let action: String = args[1].parse().expect("The first argument should be the intended action");

    if action.eq("keygen") {
        if args.len() < 6 {
            print_info();
            return Err(());
        }

        let k: usize = args[2].parse().expect("The first argument should be an integer, the threshold.");
        let n: usize = args[3].parse().expect("The second argument should be an integer, the number of parties.");
        let a: String = args[4].parse().expect("The third argument should be a string, the algorithms and groups to generate keys for.");
        let dir: String = args[5].parse().expect("The last argument should define the directory to store the keys in");
        keygen(k, n, &a, &dir);
    } else if action.eq("enc") {
        if args.len() < 5 {
            print_info();
            return Err(());
        }

        let key_path: String = args[2].parse().expect("The first argument should be the path to the key file");
        let infile: String = args[3].parse().expect("The second argument should be the path to the input file");
        let label: String = args[4].parse().expect("The third argument should be the encryption label");
        let outfile: String = args[5].parse().expect("The last argument should be the output path");

        if let Ok(e) = encrypt(&infile, label.as_bytes(), &outfile, &key_path) {
            println!("Successfully encrypted file.");
            return Ok(());
        }

        return Err(());
    } else if action.eq("verify") {
        if args.len() < 5 {
            print_info();
            return Err(());
        }

        let key_path: String = args[2].parse().expect("The first argument should be the path to the key file");
        let msgfile: String = args[3].parse().expect("The second argument should be the path to the message file");
        let signature_file: String = args[4].parse().expect("The last argument should be the path to the signature file");

        if let Ok(e) = verify(&key_path, &msgfile, &signature_file) {
            return Ok(());
        }

        return Err(());
    } else { 
        print_info();
        return Err(());
    }

    Ok(())

}

fn print_info() {
    println!("usage: ./thetacli <action> <params>");
    println!("available actions:");
    println!("- keygen <k> <n> <algorithms> <directory>");
    println!("\t generates the public/private keys for the specified schemes and groups");
    println!("\t k = threshold");
    println!("\t n = number of private keys");
    println!("\t directory = directory to store generated keys in");
    println!("\t algorithms = a list of comma separated elements of the format 'scheme-group', where 'scheme' is one of the following:");
    println!("\t\t encryption schemes: sg02, bz03");
    println!("\t\t signature schemes: bls04, frost, sh00");
    println!("\t\t coin schemes: cks05");
    println!("\t and 'group' is one of");
    println!("\t\t 'bls12381', 'bn254', 'ed25519', 'rsa512', 'rsa1024', 'rsa2048'.");
    println!("\t example: ./thetacli keygen 3 5 sg02-bls12381,bz03-ed25519 /path/to/keys/\n");
    println!("- enc <pubkey> <infile> <label> <outfile>");
    println!("\t encrypt a given infile and store it as outfile");
    println!("\t pubkey = public key of a threshold encryption scheme");
    println!("\t infile = file to be encrypted");
    println!("\t label = label for ciphertext");
    println!("\t outfile = file to store the encoded ciphertext in");
    println!("- verify <pubkey> <msg> <signature>");
    println!("\t pubkey = public key of a threshold encryption scheme");
    println!("\t msg = signed message (bytes)");
    println!("\t signature = signature to verify (hex encoded)");
}

fn keygen(k: usize, n: usize, a: &str, dir: &str) {
    let parts = a.split(',');
    let mut keys = Vec::new();
    let mut rng = RNG::new(RngAlgorithm::OsRng);

    if fs::create_dir_all(dir).is_err() {
        println!("Error: could not create directory");
        exit(-1);
    }

    for part in parts {
        let mut s = part.split('-');

        let scheme_str = s.next();
        if scheme_str.is_none() {
            println!("Invalid format of argument 'algorithms'");
            exit(-1);
        }

        let scheme = ThresholdScheme::parse_string(scheme_str.unwrap());
        if scheme.is_err() {
            println!("Invalid scheme '{}' selected", scheme_str.unwrap());
            exit(-1);
        }

        let group_str = s.next();
        if group_str.is_none() {
            println!("Invalid format of argument 'algorithms'");
            exit(-1);
        }

        let group = Group::parse_string(group_str.unwrap());
        if group.is_err() {
            println!("Invalid group '{}' selected", group_str.unwrap());
            exit(-1);
        }

        let mut name = String::from(group_str.unwrap());
        name.insert_str(0, "_");
        name.insert_str(0, scheme_str.unwrap());
        let key = KeyGenerator::generate_keys(k, n, &mut rng, &scheme.unwrap(), &group.unwrap(), &Option::None).expect("Failed to generate keys");

        let pubkey = key[0].get_public_key().serialize().unwrap();
        let file = File::create(format!("{}/{}.pub", dir, part));
        if let Err(e) = file.unwrap().write_all(&pubkey) {
            println!("Error storing public key: {}", e.to_string());
            return;
        }

        keys.insert(0, (name, key));
    }

    for node_id in 0..n {
        let mut key_chain = KeyChain::new();
        for k in &keys {
            key_chain.insert_key(k.1[node_id].clone(), k.0.clone()).expect("error generating key");
        }

        let keyfile = format!("{}/keys_{:?}.json", dir, node_id);
        key_chain.to_file(&keyfile).expect("error storing keys");
    }

    println!("Keys successfully generated.");
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