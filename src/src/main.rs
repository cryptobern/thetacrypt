#![allow(non_snake_case)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use crate::dl_schemes::{ciphers::bz03::BZ03_ThresholdCipher, dl_groups::{bls12381::Bls12381}, keygen::*, signatures::bls04::BLS04_ThresholdSignature};
use crate::dl_schemes::dl_groups::dl_group::DlGroup;
use crate::dl_schemes::ciphers::sg02::SG02_ThresholdCipher;
use crate::interface::*;
use crate::util::*;

mod interface;
mod dl_schemes;
mod bigint;
mod util;

fn main() {
    const K:u8 = 3; // threshold
    const N:u8 = 4; // total number of secret shares

    // initialize new random number generator
    let mut rng = new_rand();

    // prepare message and label
    let plaintext = "This is a test message!";
    let msg: Vec<u8> = String::from(plaintext).as_bytes().to_vec();
    let label = b"Label";
    
    println!("Message: {}", plaintext);

    println!("\n--SG02 Threshold Cipher--");

    // generate secret shares for SG02 scheme over Bls12381 curve
    let sk = DlKeyGenerator::generate_keys(&K, &N, &mut rng, &DlScheme::SG02(Bls12381::new()));
    
    // the keys are wrapped in an enum struct, so we have to unwrap them first (using the macro unwrap_keys)
    let sk = unwrap_keys!(sk, DlPrivateKey::SG02);

    // a public key is stored inside each secret share, so those can be used for encryption
    let ciphertext = SG02_ThresholdCipher::encrypt(&msg, label, &sk[0].pubkey, &mut rng); 
    
    printbinary(&ciphertext.get_msg(), Some("Ciphertext: "));

    // check whether ciphertext is valid (needed for cca security, not working properly atm)
    println!("Ciphertext valid: {}", SG02_ThresholdCipher::verify_ciphertext(&ciphertext, &sk[0].pubkey));

    // create decryption shares and verify them (verification not working properly atm)
    let mut shares = Vec::new();

    for i in 0..K {
        shares.push(SG02_ThresholdCipher::partial_decrypt(&ciphertext, sk[i as usize], &mut rng));
        println!("Share {} valid: {}", i, SG02_ThresholdCipher::verify_share(&shares[i as usize], &ciphertext, &sk[0].pubkey));
    }

    // assemble decryption shares to restore original message
    let msg = SG02_ThresholdCipher::assemble( &shares, &ciphertext);
    println!("Decrypted message: {}", hex2string(&msg));

    println!("\n--BZ03 Threshold Cipher--");

    // generate secret shares for BZ03 scheme over Bls12381 curve
    let sk = DlKeyGenerator::generate_keys(&K, &N, &mut rng, &DlScheme::BZ03(Bls12381::new()));
    
    // the keys are wrapped in an enum struct, so we have to unwrap them first (using the macro unwrap_keys)
    let sk = unwrap_keys!(sk, DlPrivateKey::BZ03);

    // a public key is stored inside each secret share, so those can be used for encryption
    let ciphertext = BZ03_ThresholdCipher::encrypt(&msg, label, &sk[0].pubkey, &mut rng); 
    
    printbinary(&ciphertext.get_msg(), Some("Ciphertext: "));

    // check whether ciphertext is valid (needed for cca security, not working properly atm)
    println!("Ciphertext valid: {}", BZ03_ThresholdCipher::verify_ciphertext(&ciphertext, &sk[0].pubkey));

    // create decryption shares and verify them (verification not working properly atm)
    let mut shares = Vec::new();

    for i in 0..K {
        shares.push(BZ03_ThresholdCipher::partial_decrypt(&ciphertext, sk[i as usize], &mut rng));
        println!("Share {} valid: {}", i, BZ03_ThresholdCipher::verify_share(&shares[i as usize], &ciphertext, &sk[0].pubkey));
    }

    // assemble decryption shares to restore original message
    let msg = BZ03_ThresholdCipher::assemble( &shares, &ciphertext);
    println!("Decrypted message: {}", hex2string(&msg));

    println!("\n--BLS04 Threshold Signature--");

    // generate secret shares for BLS04 scheme over Bls12381 curve
    let sk = DlKeyGenerator::generate_keys(&K, &N, &mut rng, &DlScheme::BLS04(Bls12381::new()));
    
    // the keys are wrapped in an enum struct, so we have to unwrap them first (using the macro unwrap_keys)
    let sk = unwrap_keys!(sk, DlPrivateKey::BLS04);
    
    let mut shares = Vec::new();

    for i in 0..K {
        shares.push(BLS04_ThresholdSignature::partial_sign(&msg, sk[i as usize]));
        println!("Partial signature {} valid: {}", i, BLS04_ThresholdSignature::verify_share(&shares[i as usize], &msg, &sk[0].pubkey));
    }

    let signature = BLS04_ThresholdSignature::assemble(&shares, &msg, &sk[0].pubkey);
    println!("Signature: {}", signature.sig.to_string());

    println!("Signature valid: {}", BLS04_ThresholdSignature::verify(&signature, &sk[0].pubkey));
}