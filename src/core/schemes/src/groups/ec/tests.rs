use rand::Rng;
use theta_proto::scheme_types::Group;

use crate::groups::group::GroupElement;
use crate::integers::sizedint::SizedBigInt;
use crate::rand::{RngAlgorithm, RNG};

use crate::groups::ec::bls12381::Bls12381;

/* Test pow, mul, div */
fn op_test(group: &Group) {
    let x = GroupElement::new_rand(group, &mut RNG::new(RngAlgorithm::OsRng));
    let y = x.pow(&SizedBigInt::new_int(group, 2));
    let z = x.mul(&x);
    let w = z.div(&x);

    assert!(y.eq(&z));
    assert!(w.eq(&x));
}

#[test]
fn test_bls12381() {
    op_test(&Group::Bls12381);
}

#[test]
fn test_ed25519() {
    op_test(&Group::Ed25519);
}

#[test]
fn test_bn254() {
    op_test(&Group::Bn254);
}
