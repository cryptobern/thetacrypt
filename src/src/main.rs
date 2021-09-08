#![allow(non_snake_case)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use mcore::rand::{RAND, RAND_impl};
use crate::dl_schemes::{dl_groups::{bls12381::Bls12381}, keygen::*};
use std::time::SystemTime;
use crate::dl_schemes::sg02::*;
use crate::interface::*;

mod interface;
mod dl_schemes;
mod bigint;

use crate::dl_schemes::dl_groups::dl_group::DlGroup;
//use crate::dl_schemes::sg02::*;

fn hex2string(msg: Vec<u8>) -> String {
    let mut res: String = String::new();
    for i in 0..msg.len() {
        res.push(msg[i] as char);
    }

    res
}

fn main() {
    const K:u8 = 3;
    const N:u8 = 5;

    let mut raw: [u8; 100] = [0; 100];
    let mut rng = RAND_impl::new();
    rng.clean();

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);

    match now {
        Ok(_n) => {
            let ms = _n.as_millis();
            for i in 0..15 {
                raw[i] = (ms << i) as u8
            }

            rng.seed(16, &raw);
        },
        Err(_) => {
            for i in 0..100 {
                raw[i] = i as u8
            }

            rng.seed(100, &raw);
        }
    }

    let plaintext = "This is a test!  ";
    let msg: Vec<u8> = String::from(plaintext).as_bytes().to_vec();
    let label: Vec<u8> = String::from("label").as_bytes().to_vec();
    println!("Message: {}", plaintext);

    println!("\n--SG02 Threshold Cipher--");

    let sk = DlKeyGenerator::generate_keys(&K, &N, &mut rng, &DlScheme::SG02(Bls12381::new()));
    let sk = unwrap_keys!(sk, DlPrivateKey::SG02);

    let ciphertext = SG02_ThresholdCipher::encrypt(&msg, &label, &sk[0].pubkey, &mut rng); 
    printbinary(&ciphertext.get_msg(), Some("Ciphertext: "));

    println!("Ciphertext valid: {}", SG02_ThresholdCipher::verify_ciphertext(&ciphertext, &sk[0].pubkey));

    let mut shares = Vec::new();
    for i in 0..K {
        shares.push(SG02_ThresholdCipher::partial_decrypt(&ciphertext, sk[i as usize], &mut rng));
        println!("Share {} valid: {}", i, SG02_ThresholdCipher::verify_share(&shares[i as usize], &ciphertext, &sk[0].pubkey));
    }

    let msg = SG02_ThresholdCipher::assemble( &shares, &ciphertext);
    println!("Decrypted message: {}", hex2string(msg));

    /*
    let (pk, sk) = bz03_gen_keys(K, N, &mut rng);
    let ciphertext = pk.encrypt(msg, &label, &mut rng);
    printbinary(&ciphertext.get_msg(), Some("Ciphertext: "));

    println!("Ciphertext valid: {}", pk.verify_ciphertext(&ciphertext));

    let mut shares = Vec::new();
    for i in 0..K {
        shares.push(sk[i as usize].partial_decrypt(&ciphertext));
        println!("Share {} valid: {}", i, pk.verify_share(&shares[i as usize], &ciphertext));
    }

    let msg = pk.assemble(&shares, &ciphertext);

    println!("Decrypted message: {}", hex2string(msg));*/
}