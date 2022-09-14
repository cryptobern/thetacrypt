use crate::{dl_schemes::signatures::frost::FrostThresholdSignature, rand::{RNG, RngAlgorithm}, proto::scheme_types::{Group, ThresholdScheme}, interface::{ThresholdSignatureParams, ThresholdSignature}, keys::KeyGenerator};


#[test]
fn test_key_generation() {
    let keys = FrostThresholdSignature::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &Group::Bls12381).unwrap();
    assert!(keys.len() == 5);
}

#[test]
fn test_signature() {
    let keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &ThresholdScheme::Frost, &Group::Bls12381, &Option::None).unwrap();
    let mut params = ThresholdSignatureParams::new();
    let msg: Vec<u8> = String::from("plaintext message").as_bytes().to_vec();
    let label = b"Label";
    let sig_share = ThresholdSignature::partial_sign(&msg, label, &keys[0], &mut params).unwrap();
    assert!(true);
}