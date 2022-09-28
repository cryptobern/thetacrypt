use crate::{rand::{RngAlgorithm, RNG}, interface::Serializable, util::printbinary};

use super::bigint::RsaBigInt;

#[test]
fn test_serialization() {
    let x = RsaBigInt::new_rand(&mut RNG::new(RngAlgorithm::MarsagliaZaman), 256);
    let x_bytes = x.serialize().unwrap();
    let decoded = RsaBigInt::deserialize(&x_bytes).unwrap();

    printbinary(&x_bytes, Some("x_bytes: "));
    assert!(x.equals(&decoded));
}

#[test]
fn test_sub() {
    let x = RsaBigInt::new_int(128);
    let y = RsaBigInt::new_int(48);
    let res = x.sub(&y);

    assert!(res.equals(&RsaBigInt::new_int(80)));

    let y = RsaBigInt::new_int(128);
    let res = x.sub(&y);

    assert!(res.equals(&RsaBigInt::new_int(0)));
}

#[test]
fn test_equals() {
    let x = RsaBigInt::new_int(128);
    let y = RsaBigInt::new_int(128);

    assert!(x.equals(&y));
}

#[test]
fn test_rand() {
    let x = RsaBigInt::new_rand(&mut RNG::new(RngAlgorithm::MarsagliaZaman), 32);
    println!("{}", x.to_string());
}