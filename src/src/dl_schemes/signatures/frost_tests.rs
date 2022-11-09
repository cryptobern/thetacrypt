use crate::{dl_schemes::signatures::frost::{FrostThresholdSignature, FrostInstance}, rand::{RNG, RngAlgorithm}, proto::scheme_types::{Group, ThresholdScheme}, keys::KeyGenerator, interface::{InteractiveThresholdSignature, InteractiveSignatureInstance}};


#[test]
fn test_key_generation() {
    let keys = FrostThresholdSignature::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &Group::Bls12381).unwrap();
    assert!(keys.len() == 5);
}

#[test]
fn test_interface() {
    let k = 3;
    let n = 5;
    let keys = KeyGenerator::generate_keys(k, n, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &ThresholdScheme::Frost, &Group::Bls12381, &Option::None).unwrap();
    assert!(keys.len() == 5);
    let mut instances = Vec::new();

    for i in 0..k {
        instances.push(InteractiveSignatureInstance::Frost(FrostInstance::new()));
    }
    
    let mut shares = Vec::new();
    let msg = b"Test message!";
    let pk = keys[0].get_public_key();

    for i in 0..ThresholdScheme::get_rounds(&ThresholdScheme::Frost) {
        println!("{} {}", i, keys.len());
        let mut round_results = Vec::new();

        // execute round i
        for j in 0..k {
            round_results.push(InteractiveThresholdSignature::sign_round(&keys[j], Option::Some(msg), &mut instances[j], i).unwrap());
        }

        //if not last round
        if i != (ThresholdScheme::get_rounds(&ThresholdScheme::Frost) - 1) {
            // broadcast results from round i to other parties
            for j in 0..k {
                assert!(instances[j].process_round_results(&round_results).is_ok());
            }
        }

        //else get signature share
        else {
            for j in 0..k {
                shares.push(round_results[j].get_share());
            }
        }
    }

    let signature = InteractiveThresholdSignature::assemble(&instances[0], &shares, msg, &pk).unwrap();
    assert!(InteractiveThresholdSignature::verify(&signature, &pk, msg).unwrap());
}

#[test]
fn test_sign() {
    /*
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
        shares.push(FrostThresholdSignature::partial_sign(&keys[i], msg, &mut instances[i]).unwrap());
        
        assert!(FrostThresholdSignature::verify_share(&shares[i], pk, &instances[i], msg).unwrap());
        //println!("{}", FrostThresholdSignature::verify_share(&shares[i], pk, &instances[i], msg).unwrap());
    }

    let signature = FrostThresholdSignature::aggregate(&instances[0], &shares).unwrap();
    assert!(FrostThresholdSignature::verify(&signature, pk, msg));
    println!("{}", FrostThresholdSignature::verify(&signature, pk, msg));*/
}