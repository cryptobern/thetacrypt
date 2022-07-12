use std::env;
use std::fs::File;
use std::io::Write;

use cosmos_crypto::dl_schemes;
// use cosmos_crypto::dl_schemes::ciphers::bz03::Bz03ThresholdCipher;
use cosmos_crypto::dl_schemes::ciphers::sg02::{Sg02ThresholdCipher, Sg02PrivateKey, Sg02PublicKey};
use cosmos_crypto::dl_schemes::dl_groups::bls12381::Bls12381;
use cosmos_crypto::dl_schemes::dl_groups::dl_group::{DlGroup, Group};
use cosmos_crypto::interface::{Serializable};
use cosmos_crypto::keygen::{KeyGenerator, PrivateKey, PublicKey, ThresholdScheme};
use cosmos_crypto::rand::{RNG, RngAlgorithm};
use protocols::keychain::KeyChain;
use protocols::pb::requests;

fn main(){
    let args: Vec<String> = env::args().collect();
    // generate_keys(3, 4);
}

fn generate_keys(k: usize, n: usize) {
    // let mut rng = RNG::new(RngAlgorithm::MarsagliaZaman);
    // // todo: Change the following to use DlKeyGenerator::generate_keys(), which returns value of type enum DlPrivateKey<D>
    // let sk_sg02_bls12381 = Sg02ThresholdCipher::generate_keys(k, n, Bls12381::new(), &mut rng);
    let sk_sg02_bls12381 = KeyGenerator::generate_keys(k, n, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &ThresholdScheme::SG02, &Group::BLS12381);
    for node_id in 1..n+1 {
        let mut key_chain = KeyChain::new();
        key_chain.insert_key(sk_sg02_bls12381[node_id].clone(), String::from("sg02_bls12381")).unwrap();
        let keyfile = format!("conf/keys_{}.json", node_id);
        key_chain.to_file(&keyfile);
    }
    
    let pk_keyfile = format!("conf/pk_sg02_bls12381.txt");
    let mut file = File::create(pk_keyfile).unwrap();
    writeln!(&mut file, "{:?}", sk_sg02_bls12381[0].get_public_key().serialize());
}