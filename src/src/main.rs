#![allow(non_snake_case)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use std::time::Instant;

use std::fmt::Write;

use crate::dl_schemes::dl_groups::dl_group::Group;
use crate::interface::{ThresholdCipherParams, ThresholdCipher, ThresholdScheme};
use crate::keys::{KeyGenerator};
use crate::rand::{RNG, RngAlgorithm};
use crate::util::{printbinary, hex2string};

mod dl_schemes;
mod interface;
mod util;
mod rsa_schemes;
mod rand;
mod keys;

fn main() {
    const K: usize = 3; // threshold
    const N: usize = 5; // total number of secret shares

    // prepare message and label
    let plaintext = "This is a test message!  ";
    let msg: Vec<u8> = String::from(plaintext).as_bytes().to_vec();
    let label = b"Label";

    println!("Message: {}", plaintext);

    // perform threshold encryption using SG02 scheme 
    println!("\n--SG02 Threshold Cipher--");

    // generate secret shares for SG02 scheme over Bls12381 curve
    let now = Instant::now();
    let sk = KeyGenerator::generate_keys(K, N, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &ThresholdScheme::SG02, &Group::BLS12381);
    let elapsed_time = now.elapsed().as_millis();
    println!("[{}ms]\tKeys generated", elapsed_time);

    // initialize new random number generator
    let mut params = ThresholdCipherParams::new();

    // a public key is stored inside each secret share, so those can be used for encryption
    let now = Instant::now();
    let ciphertext = ThresholdCipher::encrypt(&msg, label, &sk[0].get_public_key(), &mut params).unwrap();
    let elapsed_time = now.elapsed().as_millis();

    let mut s = String::with_capacity(25);
    write!(&mut s, "[{}ms]\tCiphertext: ", elapsed_time).expect("error");
    printbinary(&ciphertext.get_msg(), Some(s.as_str()));

    // check whether ciphertext is valid 
    let now = Instant::now();
    let valid = ThresholdCipher::verify_ciphertext(&ciphertext, &sk[0].get_public_key()).unwrap();
    let elapsed_time = now.elapsed().as_millis();
    println!("[{}ms]\tCiphertext valid: {}", elapsed_time, valid); 
    
    // create decryption shares and verify them 
    let mut shares = Vec::new();

    for i in 0..K {
        let now = Instant::now();
        shares.push(ThresholdCipher::partial_decrypt(&ciphertext,&sk[i as usize], &mut params).unwrap());
        let elapsed_time = now.elapsed().as_millis();

        println!("\n[{}ms]\tGenerated decryption share {}", elapsed_time, shares[i].get_id());

        let now = Instant::now();
        let valid = ThresholdCipher::verify_share(&shares[i as usize], &ciphertext, &sk[0].get_public_key()).unwrap();
        let elapsed_time = now.elapsed().as_millis();
        println!("[{}ms]\tShare {} valid: {}", elapsed_time, i, valid);
    }

    // assemble decryption shares to restore original message
    let now = Instant::now();
    let msg = ThresholdCipher::assemble(&shares, &ciphertext).unwrap();
    let elapsed_time = now.elapsed().as_millis();
    println!("[{}ms]\tDecrypted message: {}", elapsed_time, hex2string(&msg));
}
