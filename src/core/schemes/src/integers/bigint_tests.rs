use crate::{
    interface::Serializable,
    rand::{RngAlgorithm, RNG},
    util::printbinary,
};

use super::bigint::BigInt;

#[test]
fn test_serialization() {
    let x = BigInt::new_rand(&mut RNG::new(RngAlgorithm::OsRng), 256);
    let mut x_bytes = x.to_bytes();
    let decoded = BigInt::from_bytes(&mut x_bytes);

    printbinary(&x_bytes, Some("x_bytes: "));
    assert!(x.equals(&decoded));
}

#[test]
fn test_sub() {
    let x = BigInt::new_int(128);
    let y = BigInt::new_int(48);
    let res = x.sub(&y);

    assert!(res.equals(&BigInt::new_int(80)));

    let y = BigInt::new_int(128);
    let res = x.sub(&y);

    assert!(res.equals(&BigInt::new_int(0)));
}

#[test]
fn test_equals() {
    let x = BigInt::new_int(128);
    let y = BigInt::new_int(128);

    assert!(x.equals(&y));
}

#[test]
fn test_rand() {
    let x = BigInt::new_rand(&mut RNG::new(RngAlgorithm::OsRng), 32);
    println!("{}", x.to_string());
}
