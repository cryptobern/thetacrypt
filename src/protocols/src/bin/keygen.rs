use std::env;
use std::fs::File;
use std::io::Write;

use cosmos_crypto::dl_schemes::ciphers::bz03::Bz03ThresholdCipher;
use cosmos_crypto::dl_schemes::ciphers::sg02::Sg02ThresholdCipher;
use cosmos_crypto::dl_schemes::dl_groups::bls12381::Bls12381;
use cosmos_crypto::dl_schemes::dl_groups::dl_group::DlGroup;
use cosmos_crypto::rand::{RNG, RngAlgorithm};

fn main(){
    let args: Vec<String> = env::args().collect();
    let id: i32 = args[1].parse::<i32>().unwrap();
    const k: usize = 3; // threshold
    const n: usize = 4; // total number of secret shares
    let mut rng = RNG::new(RngAlgorithm::MarsagliaZaman);
    let sk_sg02_bls12381 = Sg02ThresholdCipher::generate_keys(k, n, Bls12381::new(), &mut rng);
    let sk_bz03_bls12381 = Bz03ThresholdCipher::generate_keys(k, n, Bls12381::new(), &mut rng);

    let file_sk_sg02_bls12381 = "sk_sg02_bls12381";
    let mut file = File::create(file_sk_sg02_bls12381).unwrap();
    // writeln!(&mut file, sk_sg02_bls12381[id].encode()).unwrap();

    let file_sk_bz03_bls12381 = "sk_bz03_bls12381";
    let mut file = File::create(file_sk_bz03_bls12381).unwrap();
    // writeln!(&mut file, sk_bz03_bls12381[id].encode()).unwrap();
}