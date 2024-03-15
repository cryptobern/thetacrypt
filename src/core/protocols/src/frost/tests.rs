use theta_schemes::{
    dl_schemes::signatures::frost::{FrostOptions, FrostPrivateKey},
    interface::{Group, Serializable, Signature, ThresholdScheme, ThresholdSignature},
    keys::{key_generator::KeyGenerator, keys::PrivateKeyShare},
    rand::{RngAlgorithm, RNG},
    unwrap_enum_vec,
};

use crate::{frost::protocol::FrostProtocol, interface::ThresholdRoundProtocol};

#[test]
fn test_interface() {
    let k = 3;
    let n = 5;

    let keys = KeyGenerator::generate_keys(
        k,
        n,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Frost,
        &Group::Ed25519,
        &Option::None,
    )
    .unwrap();

    assert!(keys.len() == n);

    let msg = b"Test message!";
    let pk = keys[0].get_public_key();

    let mut instances = Vec::new();

    for i in 0..k {
        let k = if let PrivateKeyShare::Frost(x) = keys[i].clone() {
            x
        } else {
            panic!("");
        };
        let instance: FrostProtocol = FrostProtocol::new(
            &k,
            msg,
            b"label",
            FrostOptions::NoPrecomputation,
            Option::None,
        );
        instances.push(instance);
    }

    let mut messages = Vec::new();

    while !instances[0].is_ready_to_finalize() {
        for i in 0..k {
            messages.push(instances[i].do_round().unwrap());
        }

        for i in 0..k {
            let mut j = 0;
            while !instances[i].is_ready_for_next_round() {
                // let result = instances[i].update(messages[j].clone());
                // match result {
                //     Ok(()) => {
                //         continue;
                //     },
                //     Err(e) => {
                //         println!("Error during update: {:?}", e);
                //     }
                // }
                assert!(instances[i].update(messages[j].clone()).is_ok());
                j += 1;
            }
        }

        messages.clear();
    }

    let signature = instances[0].finalize().unwrap();
    let result = Signature::from_bytes(&signature);

    match result {
        Ok(signature) => {
            assert!(ThresholdSignature::verify(&signature, &pk, msg).unwrap());
        },
        Err(e) => {
            println!("Error during update: {:?}", e);
        }
    }

    
}
/*
#[test]
fn test_private_key_serialization() {
    let keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Frost,
        &Group::Ed25519,
        &Option::None,
    )
    .unwrap();

    let bytes = keys[0].to_bytes();
    assert!(bytes.is_ok());
    let bytes = bytes.unwrap();
    let key = PrivateKeyShare::from_bytes(&bytes);
    assert!(key.is_ok());
    assert!(key.unwrap().eq(&keys[0]));
}

#[test]
fn test_round_result_serialization() {
    let keys = KeyGenerator::generate_keys(
        2,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Frost,
        &Group::Ed25519,
        &Option::None,
    )
    .unwrap();

    let msg = b"Hello world";
    let mut I = InteractiveThresholdSignature::new(&keys[0], msg, None).unwrap();
    let mut I1 = InteractiveThresholdSignature::new(&keys[1], msg, None).unwrap();
    let rr = I.do_round().unwrap();
    let rr1 = I1.do_round().unwrap();
    let bytes = rr.to_bytes().unwrap();
    let rr0 = RoundResult::from_bytes(&bytes);
    assert!(rr0.is_ok());
    assert!(rr0.unwrap().eq(&rr));

    let _ = I.update(&rr);
    let _ = I.update(&rr1);
    let rr2 = I.do_round();
    assert!(rr2.is_ok());
    let rr2 = rr2.unwrap();
    let bytes = rr2.to_bytes().unwrap();
    let rr0 = RoundResult::from_bytes(&bytes);
    assert!(rr0.is_ok());
    assert!(rr0.unwrap().eq(&rr2));
}

#[test]
fn test_signature_serialization() {
    let k = 3;
    let n = 5;

    let keys = KeyGenerator::generate_keys(
        k,
        n,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Frost,
        &Group::Ed25519,
        &Option::None,
    )
    .unwrap();
    assert!(keys.len() == n);

    let msg = b"Test message!";
    let pk = keys[0].get_public_key();

    let mut instances = Vec::new();

    for i in 0..k {
        let mut I = InteractiveThresholdSignature::new(&keys[i], msg, None).unwrap();
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
                j += 1;
            }
        }

        round_results.clear();
    }

    let signature = instances[0].get_signature().unwrap();

    let serialized = signature.to_bytes().unwrap();
    println!("serialized");
    let re = Signature::from_bytes(&serialized).unwrap();

    assert!(signature.eq(&re));
}

#[test]
fn test_precomputation() {
    let k = 3;
    let n = 5;

    let keys = KeyGenerator::generate_keys(
        k,
        n,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Frost,
        &Group::Ed25519,
        &Option::None,
    )
    .unwrap();
    assert!(keys.len() == n);

    let msg = b"Test message!";
    let pk = keys[0].get_public_key();

    let mut instances = Vec::new();

    for i in 0..k {
        let I = InteractiveThresholdSignature::new(
            &keys[i],
            msg,
            Some(ThresholdSignatureOptions::Frost(
                FrostOptions::Precomputation,
            )),
        )
        .unwrap();
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
                j += 1;
            }
        }

        round_results.clear();
    }

    let signature = instances[0].get_signature().unwrap();
    assert!(ThresholdSignature::verify(&signature, &pk, msg).unwrap());
}
*/
