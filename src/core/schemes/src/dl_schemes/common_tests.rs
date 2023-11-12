use crate::{
    dl_schemes::common::{eval_pol, horner, shamir_share},
    rand::{RngAlgorithm, RNG},
};

use theta_proto::scheme_types::Group;

use super::{bigint::BigImpl, dl_groups::bls12381::Bls12381};

const GROUP: Group = Group::Bls12381;

#[test]
fn test_shamir_share() {
    let x = BigImpl::new_int(&GROUP, 5);

    let mut rng = RNG::new(RngAlgorithm::OsRng);
    let (c, d) = shamir_share(&x, 2, 3, &mut rng);
    assert!(c.len() == 3);
    assert!(d.len() == 3);
}

#[test]
fn test_eval_pol() {
    let mut x = BigImpl::new_int(&GROUP, 2);
    let mut a = Vec::new();
    a.push(BigImpl::new_int(&GROUP, 1));
    a.push(BigImpl::new_int(&GROUP, 2));
    a.push(BigImpl::new_int(&GROUP, 3));

    let res = eval_pol(&mut x, &a).rmod(&BigImpl::new_int(&GROUP, 7));
    let c = BigImpl::new_int(&GROUP, 4);

    assert!(res.equals(&c));
}

#[test]
fn test_horner() {
    let mut x = BigImpl::new_int(&GROUP, 2);
    let mut a = Vec::new();
    a.push(BigImpl::new_int(&GROUP, 1));
    a.push(BigImpl::new_int(&GROUP, 2));
    a.push(BigImpl::new_int(&GROUP, 3));

    let res = horner(&mut x, &a).rmod(&BigImpl::new_int(&GROUP, 7));
    let c = BigImpl::new_int(&GROUP, 4);

    assert!(res.equals(&c));
}
