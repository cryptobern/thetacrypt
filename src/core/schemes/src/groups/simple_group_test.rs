use theta_proto::scheme_types::Group;

use super::group::GroupElement;

#[test]
fn test_eq() {
    let a = GroupElement::new(&Group::Bls12381);
    let b = a.clone();
    assert!(a == b);
}
