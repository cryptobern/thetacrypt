use theta_proto::scheme_types::Group;

use crate::{
    interface::{
        Ciphertext, DecryptionShare, Serializable, ThresholdCipher, ThresholdCipherParams,
        ThresholdScheme,
    },
    keys::{
        key_generator::KeyGenerator,
        keys::{PrivateKeyShare, PublicKey},
    },
    rand::{RngAlgorithm, RNG},
};

#[test]
fn test_public_key_serialization() {
    let private_keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Bz03,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let public_key = private_keys[0].get_public_key();
    assert!(private_keys.len() == 5);

    let public_key_encoded = public_key.to_bytes().unwrap();
    let public_key_decoded = PublicKey::from_bytes(&public_key_encoded).unwrap();
    assert!(public_key.eq(&public_key_decoded));
}

#[test]
fn test_scheme() {
    let mut params = ThresholdCipherParams::new();
    println!("generating keys");
    let private_keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Bz03,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let public_key = private_keys[0].get_public_key();
    /* Serialisation usage */

    println!("keys generated");

    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";

    println!("encrypting now");
    let ciphertext = ThresholdCipher::encrypt(&msg, label, &public_key, &mut params).unwrap();
    let mut shares = Vec::new();

    println!("encrypted");

    for i in 0..3 {
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
fn test_secret_key_serialization() {
    let private_keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Bz03,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let secret_key = private_keys[0].clone();
    let secret_key_encoded = secret_key.to_bytes().unwrap();
    let secret_key_decoded = PrivateKeyShare::from_bytes(&secret_key_encoded).unwrap();
    assert!(secret_key.eq(&secret_key_decoded));
}

#[test]
fn test_ciphertext_serialization() {
    let keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Bz03,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let mut params = ThresholdCipherParams::new();
    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";
    let ciphertext =
        ThresholdCipher::encrypt(&msg, label, &keys[0].get_public_key(), &mut params).unwrap();
    let ciphertext_encoded = ciphertext.to_bytes().unwrap();
    let ciphertext_decoded = Ciphertext::from_bytes(&ciphertext_encoded).unwrap();
    assert!(ciphertext.eq(&ciphertext_decoded));
}

#[test]
fn test_full_scheme() {
    let keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Bz03,
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

    for i in 0..3 {
        shares.push(
            ThresholdCipher::partial_decrypt(&ciphertext, &keys[i as usize], &mut params).unwrap(),
        );
        let valid = ThresholdCipher::verify_share(
            &shares[i as usize],
            &ciphertext,
            &keys[0].get_public_key(),
        )
        .unwrap();
        assert!(valid);
    }

    let decrypted = ThresholdCipher::assemble(&shares, &ciphertext).unwrap();
    assert_eq!(plaintext, decrypted);
}
#[test]
fn test_share_serialization() {
    let keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Bz03,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let mut params = ThresholdCipherParams::new();
    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";
    let ciphertext =
        ThresholdCipher::encrypt(&msg, label, &keys[0].get_public_key(), &mut params).unwrap();
    let share = ThresholdCipher::partial_decrypt(&ciphertext, &keys[0], &mut params).unwrap();
    let share_encoded = share.to_bytes().unwrap();
    let share_decoded = DecryptionShare::from_bytes(&share_encoded).unwrap();
    assert!(share.eq(&share_decoded));
}

#[test]
fn test_invalid_share() {
    let keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Bz03,
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
        &ThresholdScheme::Bz03,
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
    }
}
#[test]
fn test_valid_ciphertext() {
    let keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Bz03,
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
    assert!(ThresholdCipher::verify_ciphertext(&ciphertext, &keys[0].get_public_key()).unwrap());
}
