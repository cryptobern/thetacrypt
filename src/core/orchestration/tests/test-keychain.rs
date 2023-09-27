use std::{collections::HashMap, fs::remove_file, path::PathBuf};

use theta_schemes::{
    interface::{Serializable},
    keys::{KeyGenerator, PrivateKey},
    rand::{RngAlgorithm, RNG},
};

use theta_orchestration::keychain::KeyChain;
use theta_proto::scheme_types::{ThresholdScheme, Group};

#[test]
fn test_insert_and_get_key() {
    let (_, keys) = fill_key_chain();

    let mut key_chain = KeyChain::new();
    let default_key_id = format!("sg02_bls12381_0");
    let default_sg02_bls12381: PrivateKey = keys[&default_key_id].clone();
    let non_default_key_id = format!("sg02_bls12381_1");
    let non_default_sg02_bls12381: PrivateKey = keys[&non_default_key_id].clone();

    // insert a key
    let res = key_chain.insert_key(default_sg02_bls12381.clone(), default_key_id.clone());
    assert!(matches!(res, Ok(_)));

    // Insert again. Should return error
    let res = key_chain.insert_key(default_sg02_bls12381.clone(), default_key_id.clone());
    assert!(matches!(res, Err(_)));

    // get key by type
    let key_retrieved = &key_chain
        .get_key_by_scheme_and_group(ThresholdScheme::Sg02, Group::Bls12381)
        .expect("Should return the key just inserted")
        .sk;
    assert!(*key_retrieved == default_sg02_bls12381);

    // Insert again. Should return error
    let res = key_chain.insert_key(default_sg02_bls12381.clone(), default_key_id.clone());
    assert!(matches!(res, Err(_)));

    // insert a second key
    let res = key_chain.insert_key(
        non_default_sg02_bls12381.clone(),
        non_default_key_id.clone(),
    );
    assert!(matches!(res, Ok(_)));

    // get by type, should get back the default (first one)
    let key_retrieved = key_chain
        .get_key_by_scheme_and_group(ThresholdScheme::Sg02, Group::Bls12381)
        .expect("Should return the default key");
    assert!(key_retrieved.sk == default_sg02_bls12381);

    // get_by_id
    let key_retrieved = &key_chain
        .get_key_by_id(&default_key_id)
        .expect("Should return the first key inserted");
    assert!(key_retrieved.sk == default_sg02_bls12381);

    let key_retrieved = &key_chain
        .get_key_by_id(&non_default_key_id)
        .expect("Should return the second key inserted");
    assert!(key_retrieved.sk == non_default_sg02_bls12381);
}

#[test]
fn test_keychain_serialization() {
    let (key_chain, keys) = fill_key_chain();

    key_chain
        .to_file("tests/test_keychain_ser.txt")
        .expect("KeyChain::to_file returned Err");
    let key_chain_unser = KeyChain::from_file(&PathBuf::from("tests/test_keychain_ser.txt"))
        .expect("KeyChain::from_file returned Err");
    let _ = remove_file("tests/test_keychain_ser.txt");

    for i in 0..2 {
        let key_id = format!("sg02_bls12381_{i}");
        let sk_sg02_bls12381_unser = key_chain_unser.get_key_by_id(&key_id).unwrap();
        assert!(keys[&key_id] == sk_sg02_bls12381_unser.sk);
        assert_eq!(
            keys[&key_id].serialize().unwrap(),
            sk_sg02_bls12381_unser.sk.serialize().unwrap()
        );
    }
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
            .expect("Key with id {key_id} should be found.")
            .clone();
        assert!(key.sk.get_scheme() == ThresholdScheme::Sg02);
        assert!(key.sk.get_group() == Group::Bls12381);
        assert!(key.sk == *private_key);
    }
}

fn fill_key_chain() -> (KeyChain, HashMap<String, PrivateKey>) {
    let mut key_chain = KeyChain::new();
    let mut keys: HashMap<String, PrivateKey> = HashMap::new();
    for i in 0..2 {
        let key_id = format!("sg02_bls12381_{i}");
        let sk_sg02_bls12381 = KeyGenerator::generate_keys(
            3,
            4,
            &mut RNG::new(RngAlgorithm::MarsagliaZaman),
            &ThresholdScheme::Sg02,
            &Group::Bls12381,
            &None,
        )
        .expect("KeyGenerator::generate_keys returned Err");
        keys.insert(key_id.clone(), sk_sg02_bls12381[0].clone());
        key_chain
            .insert_key(sk_sg02_bls12381[0].clone(), key_id.clone())
            .unwrap();
    }
    (key_chain, keys)
}
