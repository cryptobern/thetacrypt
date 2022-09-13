use crate::{dl_schemes::signatures::frost::FrostThresholdSignature, rand::{RNG, RngAlgorithm}, proto::scheme_types::Group};


#[test]
fn test_key_generation() {
    let keys = FrostThresholdSignature::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &Group::Bls12381).unwrap();
    assert!(keys.len() == 5);
}