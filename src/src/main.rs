#![allow(non_snake_case)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use std::time::Instant;

use crate::dl_schemes::ciphers::sg02::Sg02ThresholdCipher;
use crate::dl_schemes::coins::cks05::Cks05ThresholdCoin;
use crate::dl_schemes::dl_groups::dl_group::DlGroup;
use crate::dl_schemes::{
    ciphers::bz03::Bz03ThresholdCipher, dl_groups::bls12381::Bls12381,
    signatures::bls04::Bls04ThresholdSignature,
};

use crate::interface::*;
use crate::rsa_schemes::signatures::sh00::Sh00ThresholdSignature;
use crate::util::*;

use std::fmt::Write;

mod bigint;
mod dl_schemes;
mod interface;
mod util;
mod rsa_schemes;

fn main() {
    const K: usize = 3; // threshold
    const N: usize = 5; // total number of secret shares

    // initialize new random number generator
    let mut rng = new_rand();

    // prepare message and label
    let plaintext = "This is a test message!  ";
    let msg: Vec<u8> = String::from(plaintext).as_bytes().to_vec();
    let label = b"Label";

    println!("Message: {}", plaintext);


    // perform threshold encryption using SG02 scheme 
    println!("\n--SG02 Threshold Cipher--");

    // generate secret shares for SG02 scheme over Bls12381 curve
    let now = Instant::now();
    let sk = Sg02ThresholdCipher::generate_keys(K, N, Bls12381::new(), &mut rng);
    let elapsed_time = now.elapsed().as_millis();
    println!("[{}ms]\tKeys generated", elapsed_time);

    // a public key is stored inside each secret share, so those can be used for encryption
    let now = Instant::now();
    let ciphertext = Sg02ThresholdCipher::encrypt(&msg, label, &sk[0].get_public_key(), &mut rng);
    let elapsed_time = now.elapsed().as_millis();

    let mut s = String::with_capacity(25);
    write!(&mut s, "[{}ms]\tCiphertext: ", elapsed_time).expect("error");
    printbinary(&ciphertext.get_msg(), Some(s.as_str()));

    // check whether ciphertext is valid 
    let now = Instant::now();
    let valid = Sg02ThresholdCipher::verify_ciphertext(&ciphertext, &sk[0].get_public_key());
    let elapsed_time = now.elapsed().as_millis();
    println!("[{}ms]\tCiphertext valid: {}", elapsed_time, valid); 
    
    // create decryption shares and verify them 
    let mut shares = Vec::new();

    for i in 0..K {
        let now = Instant::now();
        shares.push(Sg02ThresholdCipher::partial_decrypt(&ciphertext,&sk[i as usize], &mut rng));
        let elapsed_time = now.elapsed().as_millis();
        println!("\n[{}ms]\tGenerated decryption share {}", elapsed_time, shares[i].get_id());

        let now = Instant::now();
        let valid = Sg02ThresholdCipher::verify_share(&shares[i as usize], &ciphertext, &sk[0].get_public_key());
        let elapsed_time = now.elapsed().as_millis();
        println!("[{}ms]\tShare {} valid: {}", elapsed_time, i, valid);
    }

    // assemble decryption shares to restore original message
    let now = Instant::now();
    let msg = Sg02ThresholdCipher::assemble(&shares, &ciphertext);
    let elapsed_time = now.elapsed().as_millis();
    println!("[{}ms]\tDecrypted message: {}", elapsed_time, hex2string(&msg));



    // perform threshold encryption using BZ03 scheme 
    println!("\n--BZ03 Threshold Cipher--");

    // generate secret shares for BZ03 scheme over Bls12381 curve
    let now = Instant::now();
    let sk = Bz03ThresholdCipher::generate_keys(K, N, Bls12381::new(), &mut rng);
    let elapsed_time = now.elapsed().as_millis();
    println!("[{}ms]\tKeys generated", elapsed_time);

    // a public key is stored inside each secret share, so those can be used for encryption
    let now = Instant::now();
    let ciphertext = Bz03ThresholdCipher::encrypt(&msg, label, &sk[0].get_public_key(), &mut rng);
    let elapsed_time = now.elapsed().as_millis();

    let mut s = String::with_capacity(25);
    write!(&mut s, "[{}ms]\tCiphertext: ", elapsed_time).expect("error");
    printbinary(&ciphertext.get_msg(), Some(s.as_str()));

    let now = Instant::now();
    let valid = Bz03ThresholdCipher::verify_ciphertext(&ciphertext, &sk[0].get_public_key());
    let elapsed_time = now.elapsed().as_millis();

    // check whether ciphertext is valid 
    println!("[{}ms]\tCiphertext valid: {}", elapsed_time, valid);

    // create decryption shares and verify them 
    let mut shares = Vec::new();

    for i in 0..K {
        let now = Instant::now();
        shares.push(Bz03ThresholdCipher::partial_decrypt(&ciphertext,&sk[i as usize], &mut rng));
        let elapsed_time = now.elapsed().as_millis();
        println!("\n[{}ms]\tGenerated decryption share {}", elapsed_time, shares[i].get_id());

        let now = Instant::now();
        let valid = Bz03ThresholdCipher::verify_share(&shares[i as usize], &ciphertext, &sk[0].get_public_key());
        let elapsed_time = now.elapsed().as_millis();
        println!("[{}ms]\tShare {} valid: {}", elapsed_time, i, valid);
    }

    // assemble decryption shares to restore original message
    let now = Instant::now();
    let msg = Bz03ThresholdCipher::assemble(&shares, &ciphertext);
    let elapsed_time = now.elapsed().as_millis();
    println!("[{}ms]\tDecrypted message: {}", elapsed_time, hex2string(&msg));



    // create threshold signatures using BLS04 scheme 
    println!("\n--BLS04 Threshold Signature--");

    // generate secret shares for BLS04 scheme over Bls12381 curve
    let now = Instant::now();
    let sk = Bls04ThresholdSignature::generate_keys(K, N, Bls12381::new(), &mut rng);
    let elapsed_time = now.elapsed().as_millis();
    println!("[{}ms]\tKeys generated", elapsed_time);

    let mut shares = Vec::new();

    for i in 0..K {
        let now = Instant::now();
        shares.push(Bls04ThresholdSignature::partial_sign(&msg, label, &sk[i as usize]));
        let elapsed_time = now.elapsed().as_millis();
        println!("\n[{}ms]\tGenerated signature share {}", elapsed_time, shares[i].get_id());

        let now = Instant::now();
        let valid = Bls04ThresholdSignature::verify_share(&shares[i as usize], &msg, &sk[0].get_public_key());
        let elapsed_time = now.elapsed().as_millis();
        println!("[{}ms]\tPartial signature {} valid: {}", elapsed_time, i, valid);
    }

    // combine shares to generate full signature
    let now = Instant::now();
    let signature = Bls04ThresholdSignature::assemble(&shares, &msg, &sk[0].get_public_key());
    let elapsed_time = now.elapsed().as_millis();
    println!("\n[{}ms]\tSignature: {}", elapsed_time, signature.get_sig().to_string());

    // check whether signature is a valid bls signature
    let now = Instant::now();
    let valid = Bls04ThresholdSignature::verify(&signature, &sk[0].get_public_key());
    let elapsed_time = now.elapsed().as_millis();
    println!("[{}ms]\tSignature valid: {}", elapsed_time, valid);


    // create threshold signatures using SH00 scheme
    println!("\n--SH00 Threshold Signature--");

    // generate secret shares for SSH0 with 128 bit primes
    let now = Instant::now();
    let sk = Sh00ThresholdSignature::generate_keys(K, N, 512, &mut rng);
    let elapsed_time = now.elapsed().as_millis();
    println!("[{}ms]\tKeys generated", elapsed_time);

    let mut shares = Vec::new();

    for i in 0..K {
        let now = Instant::now();
        shares.push(Sh00ThresholdSignature::partial_sign(&msg, label, &sk[i as usize]));
        let elapsed_time = now.elapsed().as_millis();
        println!("\n[{}ms]\tGenerated signature share {}", elapsed_time, shares[i].get_id());
        let now = Instant::now();
        let valid =  Sh00ThresholdSignature::verify_share(&shares[i as usize], &msg, &sk[0].get_public_key());
        let elapsed_time = now.elapsed().as_millis();
        println!("[{}ms]\tPartial signature {} valid: {}", elapsed_time, shares[i].get_id(), valid);
    }

    // combine shares to generate full signature
    let now = Instant::now();
    let signature = Sh00ThresholdSignature::assemble(&shares, &msg, &sk[0].get_public_key());
    let elapsed_time = now.elapsed().as_millis();
    println!("\n[{}ms]\tSignature: {}", elapsed_time, signature.get_sig().to_string());

    // check whether signature is a valid bls signature
    let now = Instant::now();
    let valid = Sh00ThresholdSignature::verify(&signature, &sk[0].get_public_key());
    let elapsed_time = now.elapsed().as_millis();
    println!("[{}ms]\tSignature valid: {}", elapsed_time, valid);

    
    // create threshold coin using CKS05 scheme //
    println!("\n--CKS05 Threshold Coin--");

    // generate secret shares for CKS05 scheme over Bls12381 curve
    let now = Instant::now();
    let sk = Cks05ThresholdCoin::generate_keys(K, N, Bls12381::new(), &mut rng);
    let elapsed_time = now.elapsed().as_millis();
    println!("[{}ms]\tKeys generated", elapsed_time);

    let mut shares = Vec::new();
    let coin_name = b"My first threshold coin";

    for i in 0..K {
        let now = Instant::now();
        shares.push(Cks05ThresholdCoin::create_share(coin_name,&sk[i as usize], &mut rng));
        let elapsed_time = now.elapsed().as_millis();
        println!("[{}ms]\tCoin share {} valid: {}", elapsed_time, i, Cks05ThresholdCoin::verify_share(&shares[i as usize], coin_name, &sk[0].get_public_key()));
    }

    let now = Instant::now();
    let coin = Cks05ThresholdCoin::assemble(&shares);
    let elapsed_time = now.elapsed().as_millis();
    println!("[{}ms]\tCoin: {}", elapsed_time, coin.to_string());
}
