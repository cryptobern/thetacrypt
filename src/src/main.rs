#![allow(non_snake_case)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use cosmos_crypto::dl_schemes::ciphers::sg02::SG02_ThresholdCipher;
use cosmos_crypto::dl_schemes::coins::cks05::CKS05_ThresholdCoin;
use cosmos_crypto::dl_schemes::dl_groups::dl_group::DlGroup;
use cosmos_crypto::dl_schemes::{
    ciphers::bz03::BZ03_ThresholdCipher, dl_groups::bls12381::Bls12381,
    signatures::bls04::BLS04_ThresholdSignature,
};
use cosmos_crypto::interface::*;
use cosmos_crypto::util::*;

fn main() {
    const K: usize = 3; // threshold
    const N: usize = 5; // total number of secret shares

    // initialize new random number generator
    let mut rng = new_rand();

    // prepare message and label
    let plaintext = "This is a test message!";
    let msg: Vec<u8> = String::from(plaintext).as_bytes().to_vec();
    let label = b"Label";

    println!("Message: {}", plaintext);



    // perform threshold encryption using SG02 scheme 
    println!("\n--SG02 Threshold Cipher--");

    // generate secret shares for SG02 scheme over Bls12381 curve
    let sk = SG02_ThresholdCipher::generate_keys(K, N, Bls12381::new(), &mut rng);
    println!("Keys generated");

    // a public key is stored inside each secret share, so those can be used for encryption
    let ciphertext = SG02_ThresholdCipher::encrypt(&msg, label, &sk[0].get_public_key(), &mut rng);

    printbinary(&ciphertext.get_msg(), Some("Ciphertext: "));

    // check whether ciphertext is valid 
    println!("Ciphertext valid: {}", SG02_ThresholdCipher::verify_ciphertext(&ciphertext, &sk[0].get_public_key()));

    // create decryption shares and verify them 
    let mut shares = Vec::new();

    for i in 0..K {
        shares.push(SG02_ThresholdCipher::partial_decrypt(&ciphertext,&sk[i as usize], &mut rng));
        println!("Share {} valid: {}", i, SG02_ThresholdCipher::verify_share(&shares[i as usize], &ciphertext, &sk[0].get_public_key()));
    }

    // assemble decryption shares to restore original message
    let msg = SG02_ThresholdCipher::assemble(&shares, &ciphertext);
    println!("Decrypted message: {}", hex2string(&msg));



    // perform threshold encryption using BZ03 scheme 
    println!("\n--BZ03 Threshold Cipher--");

    // generate secret shares for BZ03 scheme over Bls12381 curve
    let sk = BZ03_ThresholdCipher::generate_keys(K, N, Bls12381::new(), &mut rng);
    println!("Keys generated");

    // a public key is stored inside each secret share, so those can be used for encryption
    let ciphertext = BZ03_ThresholdCipher::encrypt(&msg, label, &sk[0].get_public_key(), &mut rng);

    printbinary(&ciphertext.get_msg(), Some("Ciphertext: "));

    // check whether ciphertext is valid 
    println!("Ciphertext valid: {}", BZ03_ThresholdCipher::verify_ciphertext(&ciphertext, &sk[0].get_public_key()));

    // create decryption shares and verify them 
    let mut shares = Vec::new();

    for i in 0..K {
        shares.push(BZ03_ThresholdCipher::partial_decrypt(&ciphertext,&sk[i as usize], &mut rng));
        println!("Share {} valid: {}", i, BZ03_ThresholdCipher::verify_share(&shares[i as usize], &ciphertext, &sk[0].get_public_key()));
    }

    // assemble decryption shares to restore original message
    let msg = BZ03_ThresholdCipher::assemble(&shares, &ciphertext);
    println!("Decrypted message: {}", hex2string(&msg));



    // create threshold signatures using BLS04 scheme 
    println!("\n--BLS04 Threshold Signature--");

    // generate secret shares for BLS04 scheme over Bls12381 curve
    let sk = BLS04_ThresholdSignature::generate_keys(K, N, Bls12381::new(), &mut rng);
    println!("Keys generated");

    let mut shares = Vec::new();

    for i in 0..K {
        shares.push(BLS04_ThresholdSignature::partial_sign(&msg, &sk[i as usize]));
        println!("Partial signature {} valid: {}", i, BLS04_ThresholdSignature::verify_share(&shares[i as usize], &msg, &sk[0].get_public_key()));
    }

    // combine shares to generate full signature
    let signature = BLS04_ThresholdSignature::assemble(&shares, &msg);
    println!("Signature: {}", signature.get_sig().to_string());

    // check whether signature is a valid bls signature
    println!("Signature valid: {}", BLS04_ThresholdSignature::verify(&signature, &sk[0].get_public_key()));


    
    // create threshold coin using CKS05 scheme //
    println!("\n--CKS05 Threshold Coin--");

    // generate secret shares for CKS05 scheme over Bls12381 curve
    let sk = CKS05_ThresholdCoin::generate_keys(K, N, Bls12381::new(), &mut rng);
    println!("Keys generated");

    let mut shares = Vec::new();
    let coin_name = b"My first threshold coin";

    for i in 0..K {
        shares.push(CKS05_ThresholdCoin::create_share(coin_name,&sk[i as usize], &mut rng));
        println!("Coin share {} valid: {}", i, CKS05_ThresholdCoin::verify_share(&shares[i as usize], coin_name, &sk[0].get_public_key()));
    }

    let coin = CKS05_ThresholdCoin::assemble(&shares);
    println!("Coin: {}", coin.to_string());
}
