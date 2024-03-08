use theta_proto::scheme_types::Group;

use crate::{groups::ec::bls12381::Bls12381, integers::sizedint::SizedBigInt};

const GROUP: Group = Group::Bls12381;

#[test]
fn test_add() {
    let a = SizedBigInt::new_int(&GROUP, 5);
    let b = SizedBigInt::new_int(&GROUP, 10);
    let c = a.add(&b);
    let d = SizedBigInt::new_int(&GROUP, 15);

    assert!(c.equals(&d));
}

#[test]
fn test_mul() {
    let a = SizedBigInt::new_int(&GROUP, 5);
    let b = SizedBigInt::new_int(&GROUP, 10);
    let c = a.mul_mod(&b, &a);
    let d = SizedBigInt::new_int(&GROUP, 0);

    assert!(c.equals(&d));
}

#[test]
fn test_imul() {
    let a = SizedBigInt::new_int(&GROUP, 5);
    let b = a.imul(20);
    let c = SizedBigInt::new_int(&GROUP, 100);

    assert!(b.equals(&c));
}

#[test]
fn test_pow_mod() {
    let mut a = SizedBigInt::new_int(&GROUP, 5);
    let b = SizedBigInt::new_int(&GROUP, 2);
    let c = SizedBigInt::new_int(&GROUP, 23);
    let d = a.pow_mod(&b, &c);
    let e = SizedBigInt::new_int(&GROUP, 2);

    assert!(d.equals(&e));
    assert!(a.equals(&SizedBigInt::new_int(&GROUP, 5)));
}

#[test]
fn test_inv_mod() {
    let a = SizedBigInt::new_int(&GROUP, 3);
    let b = SizedBigInt::new_int(&GROUP, 7);
    let c = a.inv_mod(&b);
    let d = SizedBigInt::new_int(&GROUP, 5);

    assert!(c.equals(&d));
}

#[test]
fn test_rmod() {
    let a = SizedBigInt::new_int(&GROUP, 15);
    let b = SizedBigInt::new_int(&GROUP, 10);
    let c = a.rmod(&b);
    let d = SizedBigInt::new_int(&GROUP, 5);

    assert!(c.equals(&d));
}
