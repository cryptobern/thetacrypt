use crate::{dl_schemes::signatures::frost::{FrostThresholdSignature}, rand::{RNG, RngAlgorithm}, keys::{KeyGenerator, PrivateKey}, interface::{InteractiveThresholdSignature, ThresholdScheme, Serializable, RoundResult, Signature}, group::Group};


#[test]
fn test_interface() {
    let k = 3;
    let n = 5;

    let keys = KeyGenerator::generate_keys(k, n, 
                        &mut RNG::new(RngAlgorithm::MarsagliaZaman), 
                            &ThresholdScheme::Frost, 
                            &Group::Ed25519, 
                            &Option::None).unwrap();
    assert!(keys.len() == n);
    
    let msg = b"Test message!";
    let pk = keys[0].get_public_key();

    let mut instances = Vec::new();

    for i in 0..k {
        let mut I = InteractiveThresholdSignature::new(&keys[i]).unwrap();
        assert!(I.set_msg(msg).is_ok());
        instances.push(I);
    }

    let mut round_results = Vec::new();

    while !instances[0].is_finished() {
        for i in 0..k {
            round_results.push(instances[i].do_round().unwrap());
        }

        for i in 0..k {
            let mut j = 0;
            while !instances[i].is_ready_for_next_round() {
                assert!(instances[i].update(&round_results[j]).is_ok());
                j+=1;
            }
        }

        round_results.clear();
    }

    let signature = instances[0].get_signature().unwrap();

    assert!(InteractiveThresholdSignature::verify(&signature, &pk, msg).unwrap());
}


#[test]
fn test_serialization() {
    let keys = KeyGenerator::generate_keys(3, 5, 
        &mut RNG::new(RngAlgorithm::MarsagliaZaman), 
            &ThresholdScheme::Frost, 
            &Group::Bls12381, 
            &Option::None).unwrap();

    let bytes = keys[0].serialize();
    assert!(bytes.is_ok());
    let bytes = bytes.unwrap();
    let key = PrivateKey::deserialize(&bytes);
    assert!(key.is_ok());
    assert!(key.unwrap().eq(&keys[0]));
}

#[test]
fn test_round_result_serialization() {
    let keys = KeyGenerator::generate_keys(2, 5, 
        &mut RNG::new(RngAlgorithm::MarsagliaZaman), 
            &ThresholdScheme::Frost, 
            &Group::Bls12381, 
            &Option::None).unwrap();

    let mut I = InteractiveThresholdSignature::new(&keys[0]).unwrap();
    let mut I1 = InteractiveThresholdSignature::new(&keys[1]).unwrap();
    I.set_msg("msg".as_bytes());
    let rr = I.do_round().unwrap();
    let rr1 = I1.do_round().unwrap();
    let bytes = rr.serialize().unwrap();
    let rr0 = RoundResult::deserialize(&bytes);
    assert!(rr0.is_ok());
    assert!(rr0.unwrap().eq(&rr));

    I.update(&rr);
    I.update(&rr1);
    let rr2 = I.do_round();
    assert!(rr2.is_ok());
    let rr2 = rr2.unwrap();
    let bytes = rr2.serialize().unwrap();
    let rr0 = RoundResult::deserialize(&bytes);
    assert!(rr0.is_ok());
    assert!(rr0.unwrap().eq(&rr2));

}


#[test]
fn test_signature_serialization() {
    let k = 3;
    let n = 5;

    let keys = KeyGenerator::generate_keys(k, n, 
                        &mut RNG::new(RngAlgorithm::MarsagliaZaman), 
                            &ThresholdScheme::Frost, 
                            &Group::Ed25519, 
                            &Option::None).unwrap();
    assert!(keys.len() == n);
    
    let msg = b"Test message!";
    let pk = keys[0].get_public_key();

    let mut instances = Vec::new();

    for i in 0..k {
        let mut I = InteractiveThresholdSignature::new(&keys[i]).unwrap();
        assert!(I.set_msg(msg).is_ok());
        instances.push(I);
    }

    let mut round_results = Vec::new();

    while !instances[0].is_finished() {
        for i in 0..k {
            round_results.push(instances[i].do_round().unwrap());
        }

        for i in 0..k {
            let mut j = 0;
            while !instances[i].is_ready_for_next_round() {
                assert!(instances[i].update(&round_results[j]).is_ok());
                j+=1;
            }
        }

        round_results.clear();
    }

    let signature = instances[0].get_signature().unwrap();

    let serialized = signature.serialize().unwrap();
    println!("serialized");
    let re = Signature::deserialize(&serialized).unwrap();

    assert!(signature.eq(&re));
}
