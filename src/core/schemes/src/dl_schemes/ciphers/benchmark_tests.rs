use std::time::Instant;

use rand::Rng;

use crate::{keys::KeyGenerator, rand::{RNG, RngAlgorithm}, interface::{ThresholdScheme, ThresholdCipherParams, ThresholdCipher, Ciphertext, Serializable}, group::Group};

#[test]
fn serialization() {
    let mut keygen_rng = RNG::new(RngAlgorithm::OsRng);
    let private_keys = KeyGenerator::generate_keys(
        7,
        22,
        &mut keygen_rng,
        &ThresholdScheme::Sg02,
        &Group::Bls12381,
        &Option::None,
    )
    .unwrap();
    let private_key = &private_keys[0];
    let public_key = private_key.get_public_key();

    let msg_sizes = vec![1, 16, 256, 4096, 65536, 1048576, 16777216];
    let mut rng = rand::thread_rng();

    let label = vec![0, 1, 2, 3];

    println!("step,message_size,time_microseconds");

    for size in msg_sizes {
        let msg: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
        let ctxt =
            ThresholdCipher::encrypt(&msg, &label, &public_key, &mut ThresholdCipherParams::new())
                .unwrap();

        let mut ser_delta = 0;
        let mut der_delta = 0;
        for i in 0..10 {
            let now = Instant::now();
            let bytes = ctxt.serialize().unwrap();
            ser_delta += (Instant::now() - now).as_micros();
            
            let now = Instant::now();
            let _ = Ciphertext::deserialize(&bytes).unwrap();
            der_delta += (Instant::now() - now).as_micros();
        }
        ser_delta /= 10;
        der_delta /= 10;

        println!("ctxt_serialization,{},{}", size, ser_delta);
        println!("ctxt_deserialization,{},{}", size, der_delta);
    }

    assert!(1==2);
}