use crate::{dl_schemes::signatures::frost::FrostThresholdSignature, rand::{RNG, RngAlgorithm}, proto::scheme_types::Group};


#[test]
fn test_key_generation() {
    let keys = FrostThresholdSignature::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &Group::Bls12381).unwrap();
    assert!(keys.len() == 5);
}

#[test]
fn test_sign() {
    let k = 3;
    let keys = FrostThresholdSignature::generate_keys(k, 5, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &Group::Bls12381).unwrap();
    let mut commits = Vec::new();
    let mut shares = Vec::new();
    let msg = b"Test message!";
    let pk = &keys[0].get_public_key();

    let mut instances = Vec::new();

    for i in 0..k {
        instances.push(FrostThresholdSignature::commit(&keys[i], &mut RNG::new(RngAlgorithm::MarsagliaZaman)));
        commits.push(instances[i].get_commitment().clone());
    }

    for i in 0..k {
        println!("{}", commits[i].get_id());
    }

    for i in 0..k {
        shares.push(FrostThresholdSignature::partial_sign(&keys[i], msg, &commits, &mut instances[i]).unwrap());
        println!("{}", FrostThresholdSignature::verify_share(&shares[i], pk, &instances[i], msg).unwrap());
    }

    let signature = FrostThresholdSignature::aggregate(&instances[0], &shares).unwrap();
    println!("{}", FrostThresholdSignature::verify(&signature, pk, msg));
}