use std::collections::HashMap;
use crate::{keychain::KeyChain, proto::protocol_types::PublicKeyEntry};
use schemes::{keys::{KeyGenerator, PrivateKey}, rand::{RngAlgorithm, RNG}, proto::scheme_types::ThresholdScheme, proto::scheme_types::Group};

#[test]
fn test_insert_and_get_key(){
    let mut key_chain = KeyChain::new();
    let default_sg02_bls12381: PrivateKey;
    let non_default_sg02_bls12381: PrivateKey;

    // insert a key 
    let key_id = format!("sg02_bls12381_1");
    let sk_sg02_bls12381 = KeyGenerator::generate_keys(3, 4, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &ThresholdScheme::Sg02, &Group::Bls12381);
    default_sg02_bls12381 = sk_sg02_bls12381[0].clone();
    let res = key_chain.insert_key(default_sg02_bls12381.clone(), key_id.clone());
    assert!(matches!(res, Ok(_)));

    // get key by type
    let key_retrieved = key_chain.get_key_by_type(ThresholdScheme::Sg02, Group::Bls12381).expect("Should return the key just inserted").key;
    assert!(key_retrieved == default_sg02_bls12381);

    // insert same key, should return Err
    let res = key_chain.insert_key(default_sg02_bls12381.clone(), format!("sg02_bls12381_1"));
    assert!(matches!(res, Err(_)));

    // insert another key, should return ok
    let key_id = format!("sg02_bls12381_2");
    let sk_sg02_bls12381 = KeyGenerator::generate_keys(3, 4, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &ThresholdScheme::Sg02, &Group::Bls12381);
    non_default_sg02_bls12381 = sk_sg02_bls12381[0].clone();
    let res = key_chain.insert_key(non_default_sg02_bls12381.clone(), key_id.clone());
    assert!(matches!(res, Ok(_)));

    // get by type, should get back the default (first one)
    let key_retrieved = key_chain.get_key_by_type(ThresholdScheme::Sg02, Group::Bls12381).expect("Should return the default key").key;
    assert!(key_retrieved == default_sg02_bls12381);
    assert!(key_retrieved != non_default_sg02_bls12381);

    // get_by_id
    let key_retrieved = key_chain.get_key_by_id(&format!("sg02_bls12381_1")).expect("Should return the first key inserted").key;
    assert!(key_retrieved == default_sg02_bls12381);
    let key_retrieved = key_chain.get_key_by_id(&format!("sg02_bls12381_2")).expect("Should return the second key inserted").key;
    assert!(key_retrieved == non_default_sg02_bls12381);

}

#[test]
fn test_keychain_serialization(){
    let (key_chain, keys) = fill_key_chain();
    
    let key_chain_str = serde_json::to_string(&key_chain).unwrap();
    let key_chain_unser: KeyChain = serde_json::from_str(&key_chain_str).unwrap();

    for i in 0..2 {
        let key_id = format!("sg02_bls12381_{i}");
        let sk_sg02_bls12381_unser = key_chain_unser.get_key_by_id(&key_id).unwrap().key;
        assert!(keys[&key_id] ==  sk_sg02_bls12381_unser);
        assert_eq!(keys[&key_id].serialize().unwrap(), sk_sg02_bls12381_unser.serialize().unwrap());
    }
}

#[test]
fn test_get_public_keys(){
    let (key_chain, keys) = fill_key_chain();

    let public_key_entries = key_chain.get_public_keys_for_encryption().expect("get_public_keys_for_encryption() failed");
    assert!(public_key_entries.len() == 2);

    for (key_id, private_key) in keys.iter(){
        let pk_sg02_bls12381: PublicKeyEntry = public_key_entries
                                                .iter()
                                                .find(|&e| e.id == *key_id)
                                                .expect("Key with id {key_id} should be found.")
                                                .clone();
        assert!(pk_sg02_bls12381.scheme == ThresholdScheme::Sg02 as i32);
        assert!(pk_sg02_bls12381.group == Group::Bls12381 as i32);
        assert!(pk_sg02_bls12381.key == private_key.serialize().expect("Error in serializing public key"));
    }

}

fn fill_key_chain() -> (KeyChain, HashMap<String, PrivateKey>) {
    let mut key_chain = KeyChain::new();
    let mut keys: HashMap<String, PrivateKey> = HashMap::new();
    for i in 0..2 {
        let key_id = format!("sg02_bls12381_{i}");
        let sk_sg02_bls12381 = KeyGenerator::generate_keys(3, 4, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &ThresholdScheme::Sg02, &Group::Bls12381);
        keys.insert(key_id.clone(), sk_sg02_bls12381[0].clone());
        key_chain.insert_key(sk_sg02_bls12381[0].clone(), key_id.clone()).unwrap();
    }
    (key_chain, keys)
}

