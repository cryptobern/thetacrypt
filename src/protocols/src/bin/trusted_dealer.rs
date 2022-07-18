use std::env;
use std::fs::File;
use std::io::Write;
use std::thread::panicking;

use cosmos_crypto::dl_schemes;
// use cosmos_crypto::dl_schemes::ciphers::bz03::Bz03ThresholdCipher;
use cosmos_crypto::dl_schemes::ciphers::sg02::{Sg02ThresholdCipher, Sg02PrivateKey, Sg02PublicKey};
use cosmos_crypto::dl_schemes::dl_groups::bls12381::Bls12381;
use cosmos_crypto::dl_schemes::dl_groups::dl_group::{DlGroup, Group};
use cosmos_crypto::interface::{Serializable, ThresholdScheme};
use cosmos_crypto::keys::{KeyGenerator, PrivateKey, PublicKey};
use cosmos_crypto::rand::{RNG, RngAlgorithm};
use protocols::keychain::KeyChain;
use protocols::pb::requests;

fn main(){
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Two arguments expected, the threshold and the number of parties.")
    }
    let k: usize = args[1].parse().expect("The first argument should be an integer, the threshold.");
    let n: usize = args[2].parse().expect("The second argument should be an integer, the number of parties.");
    generate_keys(k, n).expect("Failed to generate keys");
}

fn generate_keys(k: usize, n: usize) -> Result<(), Box<dyn std::error::Error>>{
    // let mut rng = RNG::new(RngAlgorithm::MarsagliaZaman);
    // // todo: Change the following to use DlKeyGenerator::generate_keys(), which returns value of type enum DlPrivateKey<D>
    // let sk_sg02_bls12381 = Sg02ThresholdCipher::generate_keys(k, n, Bls12381::new(), &mut rng);
    let sk_sg02_bls12381 = KeyGenerator::generate_keys(k,
                                                                        n, 
                                                                        &mut RNG::new(RngAlgorithm::MarsagliaZaman),
                                                                        &ThresholdScheme::SG02,
                                                                        &Group::BLS12381);
    for node_id in 0..n {
        let mut key_chain = KeyChain::new();
        key_chain.insert_key(sk_sg02_bls12381[node_id].clone(), String::from("sg02_bls12381"))?;
        // attention: Nodes use ids 1 to n
        let keyfile = format!("conf/keys_{:?}.json", node_id + 1);
        key_chain.to_file(&keyfile)?;
    }
    Ok(())
}