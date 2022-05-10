use crate::{rand::{RngAlgorithm, RNG}, interface::Serializable, util::printbinary};

use super::bigint::BigInt;

#[test]
fn test_serialization() {
    let x = BigInt::new_rand(&mut RNG::new(RngAlgorithm::MarsagliaZaman), 256);
    let x_bytes = x.serialize().unwrap();
    let decoded = BigInt::deserialize(&x_bytes).unwrap();

    println!("x: {}", x.to_string());
    printbinary(&x_bytes, Some("x_bytes: "));
    println!("decoded: {}", x.to_string());


    assert!(x.equals(&decoded));
}