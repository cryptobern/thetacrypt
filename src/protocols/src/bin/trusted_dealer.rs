use std::{env, process::exit};

use rand::rngs::OsRng;
use schemes::{keys::{KeyGenerator, PrivateKey}, interface::ThresholdScheme, group::Group, rand::{RNG, RngAlgorithm}};
use protocols::keychain::KeyChain;
use std::fs;

fn main(){
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        println!("usage: ./trusted_dealer <k> <n> <algorithms>");
        println!("k = threshold, n = number of private keys");
        println!("The format of the 'algorithms' parameter is as follows:");
        println!("A list of comma separated elements of the format 'scheme-group' where 'scheme' is one of");
        println!("'sg02', 'bz03', 'cks05', 'bls04', 'frost', 'sh00' and 'group' is one of");
        println!("'bls12381', 'bn254', 'ed25519', 'rsa512', 'rsa1024', 'rsa2048'.");
        return;
    }
    let k: usize = args[1].parse().expect("The first argument should be an integer, the threshold.");
    let n: usize = args[2].parse().expect("The second argument should be an integer, the number of parties.");
    let a: String = args[3].parse().expect("The third argument should be a string, the algorithms and groups to generate keys for.");
    
    let parts = a.split(',');

    let mut keys = Vec::new();
    let mut rng = RNG::new(RngAlgorithm::OsRng);
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

        keys.insert(0, (name, key));
    }

    if fs::create_dir_all("conf").is_err() {
        println!("Error: could not create directory");
        exit(-1);
    }

    for node_id in 0..n {
        let mut key_chain = KeyChain::new();
        for k in &keys {
            key_chain.insert_key(k.1[node_id].clone(), k.0.clone()).expect("error generating key");
        }

        let keyfile = format!("conf/keys_{:?}.json", node_id);
        key_chain.to_file(&keyfile).expect("error storing keys");
    }

    println!("Keys successfully generated.");

}

fn generate_keys(k: usize, n: usize) -> Result<(), Box<dyn std::error::Error>>{
    let sk_sg02_bls12381 = KeyGenerator::generate_keys(
        k,
        n, 
        &mut RNG::new(RngAlgorithm::MarsagliaZaman),
        &ThresholdScheme::Sg02,
        &Group::Bls12381,
        &Option::None).unwrap();
    for node_id in 0..n {
        let mut key_chain = KeyChain::new();
        key_chain.insert_key(sk_sg02_bls12381[node_id].clone(), String::from("sg02_bls12381"))?;
        let keyfile = format!("config/keys_{:?}.json", node_id);
        key_chain.to_file(&keyfile)?;
    }
    Ok(())
}