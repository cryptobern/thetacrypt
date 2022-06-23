use std::env;
use std::fs::File;
use std::io::Write;

use cosmos_crypto::dl_schemes;
use cosmos_crypto::dl_schemes::ciphers::bz03::Bz03ThresholdCipher;
use cosmos_crypto::dl_schemes::ciphers::sg02::{Sg02ThresholdCipher, Sg02PrivateKey, Sg02PublicKey};
use cosmos_crypto::dl_schemes::dl_groups::bls12381::Bls12381;
use cosmos_crypto::dl_schemes::dl_groups::dl_group::DlGroup;
use cosmos_crypto::dl_schemes::keygen::DlKeyGenerator;
use cosmos_crypto::interface::{Serializable, PrivateKey};
use cosmos_crypto::rand::{RNG, RngAlgorithm};
use protocols::keychain::KeyChain;
use protocols::pb::requests;

fn main(){
    let args: Vec<String> = env::args().collect();
    generate_keys(3, 4);
}

fn generate_keys(k: usize, n: usize) {
    let mut rng = RNG::new(RngAlgorithm::MarsagliaZaman);
    // todo: Change the following to use DlKeyGenerator::generate_keys(), which returns value of type enum DlPrivateKey<D>
    let sk_sg02_bls12381 = Sg02ThresholdCipher::generate_keys(k, n, Bls12381::new(), &mut rng);
    for node_id in 0..n {
        let mut key_chain = KeyChain::new();
        key_chain.insert_key(requests::ThresholdCipher::Sg02, 
                             requests::DlGroup::Bls12381, 
                             String::from("sg02_bls12381"),
                             sk_sg02_bls12381[node_id].serialize().unwrap());
        // key_chain.insert_key(requests::ThresholdCipher::Bz02, 
        //                      requests::DlGroup::Bls12381, 
        //                      String::from("bz03_bls12381"),
        //                      sk_bz03_bls12381[node_id].serialize().unwrap());
        let keyfile = format!("conf/keys_{}.json", node_id);
        let mut file = File::create(keyfile).unwrap();
        println!("{}", serde_json::to_string(&key_chain).unwrap());
        writeln!(&mut file, "{}", serde_json::to_string(&key_chain).unwrap()).unwrap();
    }
    let mut key_chain_pk = KeyChain::new();
    key_chain_pk.insert_key(requests::ThresholdCipher::Sg02, 
                            requests::DlGroup::Bls12381, 
                            String::from("sg02_bls12381"),
                            sk_sg02_bls12381[0].get_public_key().serialize().unwrap());
    // key_chain.insert_key(requests::ThresholdCipher::Bz02, 
    //                      requests::DlGroup::Bls12381, 
    //                      String::from("bz03_bls12381"),
    //                      sk_bz03_bls12381[node_id].serialize().unwrap());
    let keyfile = format!("conf/pk.json");
    let mut file = File::create(keyfile).unwrap();
    println!("{}", serde_json::to_string(&key_chain_pk).unwrap());
    writeln!(&mut file, "{}", serde_json::to_string(&key_chain_pk).unwrap()).unwrap();
}