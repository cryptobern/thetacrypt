use crate::{dl_schemes::signatures::frost::{FrostThresholdSignature}, rand::{RNG, RngAlgorithm}, proto::scheme_types::{Group, ThresholdScheme}, keys::KeyGenerator, interface::{InteractiveThresholdSignature}};


#[test]
fn test_interface() {
    let k = 3;
    let n = 5;

    let keys = KeyGenerator::generate_keys(k, n, 
                        &mut RNG::new(RngAlgorithm::MarsagliaZaman), 
                            &ThresholdScheme::Frost, 
                            &Group::Bls12381, 
                            &Option::None).unwrap();
    assert!(keys.len() == n);
    
    let msg = b"Test message!";
    let pk = keys[0].get_public_key();

    let mut instances = Vec::new();

    for _ in 0..k {
        let I = InteractiveThresholdSignature::new(&keys[0], msg).unwrap();
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

    //let signature = instances[0].get_signature().unwrap();

   // InteractiveThresholdSignature::verify(&signature, &pk, msg);
}
