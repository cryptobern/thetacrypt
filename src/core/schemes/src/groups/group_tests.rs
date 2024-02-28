use crate::groups::ec::bls12381::Bls12381;
use crate::groups::group::GroupElement;
use crate::integers::sizedint::SizedBigInt;
use crate::rand::RNG;
use rand::Rng;
use theta_proto::scheme_types::Group;

static GROUP: Group = Group::Bls12381;

#[test]
fn test_mul() {
    let int3: SizedBigInt = SizedBigInt::new_int(&GROUP, 3);
    let int5: SizedBigInt = SizedBigInt::new_int(&GROUP, 5);
    let int8: SizedBigInt = SizedBigInt::new_int(&GROUP, 8);

    let a = GroupElement::new_pow_big(&GROUP, &int3);
    let b = GroupElement::new_pow_big(&GROUP, &int5);
    let c = a.mul(&b);
    let d = GroupElement::new_pow_big(&GROUP, &int8);

    assert!(c.eq(&d));

    let c = a.mul(&b).mul(&b).mul(&a);
    let d = GroupElement::new_pow_big(&GROUP, &SizedBigInt::new_int(&GROUP, 16));
    assert!(c.eq(&d));
}

#[test]
fn test_ecp2_mul() {
    let int3: SizedBigInt = SizedBigInt::new_int(&GROUP, 3);
    let int5: SizedBigInt = SizedBigInt::new_int(&GROUP, 5);
    let int8: SizedBigInt = SizedBigInt::new_int(&GROUP, 8);

    let a = GroupElement::new_pow_big_ecp2(&GROUP, &int3);
    let b = GroupElement::new_pow_big_ecp2(&GROUP, &int5);
    let c = a.mul(&b);
    let d = GroupElement::new_pow_big_ecp2(&GROUP, &int8);

    assert!(c.eq(&d));

    let c = a.mul(&b).mul(&b).mul(&a);
    let d = GroupElement::new_pow_big_ecp2(&GROUP, &SizedBigInt::new_int(&GROUP, 16));
    assert!(c.eq(&d));
}

#[test]
fn test_div() {
    let int3: SizedBigInt = SizedBigInt::new_int(&GROUP, 3);
    let int5: SizedBigInt = SizedBigInt::new_int(&GROUP, 5);
    let int8: SizedBigInt = SizedBigInt::new_int(&GROUP, 8);

    let a = GroupElement::new_pow_big(&GROUP, &int8);
    let b = GroupElement::new_pow_big(&GROUP, &int5);
    let c = a.div(&b);
    let d = GroupElement::new_pow_big(&GROUP, &int3);

    assert!(c.eq(&d));
}

#[test]
fn test_div_ecp2() {
    let int3: SizedBigInt = SizedBigInt::new_int(&GROUP, 3);
    let int5: SizedBigInt = SizedBigInt::new_int(&GROUP, 5);
    let int8: SizedBigInt = SizedBigInt::new_int(&GROUP, 8);

    let a = GroupElement::new_pow_big_ecp2(&GROUP, &int8);
    let b = GroupElement::new_pow_big_ecp2(&GROUP, &int5);
    let c = a.div(&b);
    let d = GroupElement::new_pow_big_ecp2(&GROUP, &int3);

    assert!(c.eq(&d));
}

#[test]
fn test_pow() {
    let int3: SizedBigInt = SizedBigInt::new_int(&GROUP, 3);
    let int5: SizedBigInt = SizedBigInt::new_int(&GROUP, 5);
    let int15: SizedBigInt = SizedBigInt::new_int(&GROUP, 15);

    let a = GroupElement::new_pow_big(&GROUP, &int3);
    let b = a.pow(&int5);
    let c = GroupElement::new_pow_big(&GROUP, &int15);

    assert!(b.eq(&c));
}

#[test]
fn test_pow_ecp2() {
    let int3: SizedBigInt = SizedBigInt::new_int(&GROUP, 3);
    let int5: SizedBigInt = SizedBigInt::new_int(&GROUP, 5);
    let int15: SizedBigInt = SizedBigInt::new_int(&GROUP, 15);

    let a = GroupElement::new_pow_big_ecp2(&GROUP, &int3);
    let b = a.pow(&int5);
    let c = GroupElement::new_pow_big_ecp2(&GROUP, &int15);

    assert!(b.eq(&c));
}

#[test]
fn test_new_pow() {
    let int3: SizedBigInt = SizedBigInt::new_int(&GROUP, 3);
    let a = GroupElement::new_pow_big(&GROUP, &int3);
    let b = GroupElement::new(&GROUP).pow(&int3);

    assert!(a.eq(&b));

    let a = GroupElement::new_pow_big_ecp2(&GROUP, &int3);
    let b = GroupElement::new_ecp2(&GROUP).pow(&int3);

    assert!(a.eq(&b));
}

#[test]
fn test_schnorr() {
    let int2: SizedBigInt = SizedBigInt::new_int(&GROUP, 2);

    let a = GroupElement::new_pow_big(&GROUP, &int2);

    let res = a.pow(&int2).div(&a.pow(&int2));

    assert!(res.eq(&GroupElement::identity(&GROUP)));
}
