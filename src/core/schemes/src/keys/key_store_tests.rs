use std::{collections::HashMap, fs::remove_file, path::PathBuf};

use base64::{engine::general_purpose, Engine};
use mcore::hash256::HASH256;
use theta_proto::scheme_types::{Group, ThresholdScheme};

use crate::{
    dl_schemes::dl_groups::bls12381::Bls12381,
    interface::{Serializable, ThresholdCipherParams},
    rand::{RngAlgorithm, RNG},
};

use super::{
    key_generator::KeyGenerator,
    key_store::KeyStore,
    keys::{calc_key_id, key2id, PrivateKeyShare},
};

#[test]
pub fn test_adding_and_retrieving_keys() {
    let keypair0 = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(crate::rand::RngAlgorithm::OsRng),
        &ThresholdScheme::Sg02,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();

    let mut keystore: KeyStore = KeyStore::new();
    let result = keystore.insert_private_key(keypair0[0].clone());
    assert!(result.is_ok(), "could not add key pair");
    let id = result.unwrap();

    let keypair1 = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(crate::rand::RngAlgorithm::OsRng),
        &ThresholdScheme::Sg02,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();

    let result = keystore.insert_private_key(keypair1[0].clone());
    assert!(result.is_ok(), "could not add second key pair");

    let retrieved_key = keystore.get_key_by_id(&id);
    assert!(retrieved_key.is_ok());
    assert_eq!(
        retrieved_key.as_ref().unwrap().sk.as_ref().unwrap(),
        &keypair0[0]
    );
}

// it should not be possible to add multiple private key shares belonging to the same public key
#[test]
pub fn test_cannot_add_multiple_private_key_ids() {
    let keypair = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(crate::rand::RngAlgorithm::OsRng),
        &ThresholdScheme::Sg02,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();

    let mut keystore: KeyStore = KeyStore::new();
    let result = keystore.insert_private_key(keypair[0].clone());
    assert!(result.is_ok());
    let key_id = result.unwrap();
    let result = keystore.insert_private_key(keypair[1].clone());
    assert!(
        result.is_err(),
        "could add second private key share to existing public key"
    );
}

#[test]
fn test_keychain_serialization() {
    let (key_chain, keys) = fill_key_chain();

    key_chain
        .to_file("test_keychain_ser.txt")
        .expect("KeyStore::to_file returned Err");
    let key_chain_unser = KeyStore::from_file(&PathBuf::from("test_keychain_ser.txt"))
        .expect("KeyStore::from_file returned Err");
    let _ = remove_file("test_keychain_ser.txt");

    assert_eq!(key_chain, key_chain_unser);
}

#[test]
fn test_get_encryption_keys() {
    let (key_chain, keys) = fill_key_chain();

    let encryption_keys = key_chain.get_encryption_keys();
    assert!(encryption_keys.len() == 2);

    for (key_id, private_key) in keys.iter() {
        let key = encryption_keys
            .iter()
            .find(|&e| e.id == *key_id)
            .expect("Key with id {key_id} should be found.");
        assert!(key.sk.as_ref().unwrap().get_scheme() == ThresholdScheme::Sg02);
        assert!(Group::Bls12381.eq(key.sk.as_ref().unwrap().get_group()));
        assert!(private_key.eq(key.sk.as_ref().unwrap()));
    }
}

fn fill_key_chain() -> (KeyStore, HashMap<String, PrivateKeyShare>) {
    let mut key_chain = KeyStore::new();
    let mut keys: HashMap<String, PrivateKeyShare> = HashMap::new();
    for i in 0..2 {
        let sk_sg02_bls12381 = KeyGenerator::generate_keys(
            3,
            4,
            &mut RNG::new(RngAlgorithm::MarsagliaZaman),
            &ThresholdScheme::Sg02,
            &Group::Bls12381,
            &None,
        )
        .expect("KeyGenerator::generate_keys returned Err");

        let key_id = key2id(&sk_sg02_bls12381[0].get_public_key());

        keys.insert(key_id.clone(), sk_sg02_bls12381[0].clone());
        key_chain
            .insert_private_key(sk_sg02_bls12381[0].clone())
            .unwrap();
    }
    (key_chain, keys)
}
