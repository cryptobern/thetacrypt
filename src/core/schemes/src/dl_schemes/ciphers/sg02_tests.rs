use std::{mem::ManuallyDrop, time::Instant};

use crate::dl_schemes::bigint::SizedBigInt;
use crate::group::GroupElement;
use crate::keys::key_generator::KeyGenerator;
use crate::util::{hex2string, printbinary};
use crate::{
    dl_schemes::{
        ciphers::sg02::{Sg02Ciphertext, Sg02PublicKey},
        common::shamir_share,
    },
    interface::{
        Ciphertext, DecryptionShare, Serializable, ThresholdCipher, ThresholdCipherParams,
    },
    keys::keys::{PrivateKeyShare, PublicKey},
    rand::{RngAlgorithm, RNG},
};
use std::fmt::Write;
use theta_proto::scheme_types::{Group, ThresholdScheme};

#[test]
fn test_scheme() {
    let mut params = ThresholdCipherParams::new();
    let k = 3;
    let n = 5;
    let private_keys = KeyGenerator::generate_keys(
        k,
        n,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Sg02,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let public_key = private_keys[0].get_public_key();
    /* Serialisation usage */

    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";

    let ciphertext = ThresholdCipher::encrypt(&msg, label, &public_key, &mut params).unwrap();
    let mut shares = Vec::new();

    for i in 0..k {
        shares.push(
            ThresholdCipher::partial_decrypt(&ciphertext, &private_keys[i as usize], &mut params)
                .unwrap(),
        );
        assert!(ThresholdCipher::verify_share(&shares[i], &ciphertext, &public_key).unwrap());
    }

    let decrypted = ThresholdCipher::assemble(&shares, &ciphertext).unwrap();
    assert!(msg.eq(&decrypted));
}

#[test]
fn test_public_key_serialization() {
    let private_keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Sg02,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let public_key = private_keys[0].get_public_key();

    /* Serialisation usage */
    let public_key_encoded = public_key.to_bytes().unwrap();
    println!("{}", public_key.get_key_id());
    let public_key_decoded = PublicKey::from_bytes(&public_key_encoded).unwrap();
    println!("{}", public_key_decoded.get_key_id());
    assert!(public_key.eq(&public_key_decoded));
}

#[test]
fn test_private_key_serialization() {
    let private_keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Sg02,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let private_key_encoded = private_keys[0].to_bytes().unwrap();
    let private_key_decoded = PrivateKeyShare::from_bytes(&private_key_encoded).unwrap();
    assert!(private_keys[0].eq(&private_key_decoded));
}

#[test]
fn test_share_serialization() {
    let mut params = ThresholdCipherParams::new();

    let private_keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Sg02,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let public_key = private_keys[0].get_public_key();

    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";

    let ciphertext = ThresholdCipher::encrypt(&msg, label, &public_key, &mut params).unwrap();
    let share =
        ThresholdCipher::partial_decrypt(&ciphertext, &private_keys[0], &mut params).unwrap();

    let share_encoded = share.to_bytes().unwrap();
    let share_decoded = DecryptionShare::from_bytes(&share_encoded).unwrap();
    assert!(share.eq(&share_decoded));
}

#[test]
fn test_ciphertext_serialization() {
    let mut params = ThresholdCipherParams::new();

    let private_keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Sg02,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let public_key = private_keys[0].get_public_key();

    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";

    let ciphertext = ThresholdCipher::encrypt(&msg, label, &public_key, &mut params).unwrap();
    let ct_encoded = ciphertext.to_bytes().unwrap();
    let ct_decoded = Ciphertext::from_bytes(&ct_encoded).unwrap();
    assert!(ciphertext.eq(&ct_decoded));
}

#[test]
fn test_invalid_share() {
    let keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Sg02,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let mut params = ThresholdCipherParams::new();
    let plaintext: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";
    let mut shares = Vec::new();
    let ciphertext =
        ThresholdCipher::encrypt(&plaintext, label, &keys[0].get_public_key(), &mut params)
            .unwrap();
    let keys2 = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Sg02,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();

    for i in 0..3 {
        shares.push(
            ThresholdCipher::partial_decrypt(&ciphertext, &keys2[i as usize], &mut params).unwrap(),
        );
        let valid = ThresholdCipher::verify_share(
            &shares[i as usize],
            &ciphertext,
            &keys[0].get_public_key(),
        );
        assert!(!valid.unwrap());
        assert!(ThresholdCipher::verify_share(
            &shares[i as usize],
            &ciphertext,
            &keys2[0].get_public_key()
        )
        .unwrap())
    }
}

#[test]
fn test_invalid_ciphertext() {
    let keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Sg02,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let mut params = ThresholdCipherParams::new();
    let plaintext: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";
    let ciphertext =
        ThresholdCipher::encrypt(&plaintext, label, &keys[0].get_public_key(), &mut params)
            .unwrap();
    let keys2 = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Sg02,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();

    assert!(ThresholdCipher::verify_ciphertext(&ciphertext, &keys[0].get_public_key()).unwrap());
    assert!(!ThresholdCipher::verify_ciphertext(&ciphertext, &keys2[0].get_public_key()).unwrap());
}
