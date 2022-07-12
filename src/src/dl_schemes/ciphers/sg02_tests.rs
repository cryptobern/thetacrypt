use std::mem::ManuallyDrop;

use crate::{dl_schemes::{dl_groups::{bls12381::{Bls12381, Bls12381BIG}, dl_group::{DlGroup, GroupElement, Group, GroupData}}, bigint::{BigImpl, BigInt}, common::shamir_share, ciphers::sg02::Sg02PublicKey}, rand::{RNG, RngAlgorithm}, interface::{Serializable, ThresholdCipherParams, ThresholdCipher, DecryptionShare, Ciphertext}};
use crate::util::{printbinary, hex2string};

#[test]
fn test_scheme() {
    let mut params = ThresholdCipherParams::new();
    
    let private_keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &ThresholdScheme::SG02, &Group::BLS12381);
    let public_key = private_keys[0].get_public_key();
    /* Serialisation usage */

    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";

    let ciphertext = ThresholdCipher::encrypt(&msg, label, &public_key, &mut params).unwrap();
    let mut shares = Vec::new();
    
    for i in 0..3 {
        shares.push(ThresholdCipher::partial_decrypt(&ciphertext, &private_keys[i as usize], &mut params).unwrap());
        assert!(ThresholdCipher::verify_share(&shares[i], &ciphertext, &public_key).unwrap());
    }

    let decrypted = ThresholdCipher::assemble(&shares, &ciphertext).unwrap();
    assert!(msg.eq(&decrypted));
}


#[test]
fn test_public_key_serialization() {
    let mut params = ThresholdCipherParams::new();
    
    let private_keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &ThresholdScheme::SG02, &Group::BLS12381);
    let public_key = private_keys[0].get_public_key();
    /* Serialisation usage */

    let public_key_encoded = public_key.serialize().unwrap();
    let public_key_decoded = PublicKey::deserialize(&public_key_encoded);
    assert!(public_key.eq(&public_key_decoded));

    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";

    let ciphertext = ThresholdCipher::encrypt(&msg, label, &public_key, &mut params).unwrap();
    let share = ThresholdCipher::partial_decrypt(&ciphertext, &private_keys[0], &mut params).unwrap();
}

#[test]
fn test_share_serialization() {
    let mut params = ThresholdCipherParams::new();
    
    let private_keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &ThresholdScheme::SG02, &Group::BLS12381);
    let public_key = private_keys[0].get_public_key();   

    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";

    let ciphertext = ThresholdCipher::encrypt(&msg, label, &public_key, &mut params).unwrap();
    let share = ThresholdCipher::partial_decrypt(&ciphertext, &private_keys[0], &mut params).unwrap();

    let share_encoded = share.serialize().unwrap();
    let share_decoded = DecryptionShare::deserialize(&share_encoded);
    assert!(share.eq(&share_decoded));
}

#[test]
fn test_ciphertext_serialization() {
    let mut params = ThresholdCipherParams::new();
    
    let private_keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &ThresholdScheme::SG02, &Group::BLS12381);
    let public_key = private_keys[0].get_public_key();

    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";

    let ciphertext = ThresholdCipher::encrypt(&msg, label, &public_key, &mut params).unwrap();
    let ct_encoded = ciphertext.serialize().unwrap();
    let ct_decoded = Ciphertext::deserialize(&ct_encoded);
    assert!(ciphertext.eq(&ct_decoded));
}