use super::cks05::*;
use crate::{
    dl_schemes::dl_groups::bls12381::Bls12381,
    interface::{CoinShare, Serializable, ThresholdCoin},
    keys::{KeyGenerator, PublicKey},
    rand::{RngAlgorithm, RNG},
    util::printbinary,
};
use theta_proto::scheme_types::{Group, ThresholdScheme};

#[test]
fn test_key_generation() {
    let keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Cks05,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    assert!(keys.len() == 5);
}

#[test]
fn test_public_key_serialization() {
    let private_keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Cks05,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let public_key = private_keys[0].get_public_key();
    assert!(private_keys.len() == 5);

    let public_key_encoded = public_key.serialize().unwrap();
    let public_key_decoded = PublicKey::deserialize(&public_key_encoded).unwrap();
    assert!(public_key.eq(&public_key_decoded));
}

#[test]
fn test_share_creation() {
    let private_keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Cks05,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let name = b"Label";
    let share =
        ThresholdCoin::create_share(name, &private_keys[0], &mut RNG::new(RngAlgorithm::OsRng))
            .unwrap();
    let valid =
        ThresholdCoin::verify_share(&share, name, &private_keys[0].get_public_key()).unwrap();
    assert!(valid);
}

#[test]
fn test_share_serialization() {
    let private_keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Cks05,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let name = b"Label";
    let share =
        ThresholdCoin::create_share(name, &private_keys[0], &mut RNG::new(RngAlgorithm::OsRng))
            .unwrap();

    let share_encoded = share.serialize().unwrap();
    let share_decoded = CoinShare::deserialize(&share_encoded).unwrap();

    assert!(share.eq(&share_decoded));
}

#[test]
fn test_full_scheme() {
    let keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Cks05,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let name = b"My Coin";
    let mut shares = Vec::new();

    for i in 0..5 {
        shares.push(
            ThresholdCoin::create_share(
                name,
                &keys[i as usize],
                &mut RNG::new(RngAlgorithm::OsRng),
            )
            .unwrap(),
        );
        let valid =
            ThresholdCoin::verify_share(&shares[i as usize], name, &keys[0].get_public_key())
                .unwrap();
        assert!(valid);
    }

    let coin1 = ThresholdCoin::assemble(&shares[0..3].to_vec()).unwrap();
    let coin2 = ThresholdCoin::assemble(&shares[1..4].to_vec()).unwrap();
    assert_eq!(coin1, coin2);
    assert!(coin1 < 2 && coin1 >= 0);
}

#[test]
fn test_invalid_share() {
    let keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Cks05,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let name = b"Label";
    let mut shares = Vec::new();
    let keys2 = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Cks05,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();

    for i in 0..3 {
        shares.push(
            ThresholdCoin::create_share(
                name,
                &keys2[i as usize],
                &mut RNG::new(RngAlgorithm::OsRng),
            )
            .unwrap(),
        );
        let valid =
            ThresholdCoin::verify_share(&shares[i as usize], name, &keys[0].get_public_key())
                .unwrap();
        assert!(!valid);
    }
}
