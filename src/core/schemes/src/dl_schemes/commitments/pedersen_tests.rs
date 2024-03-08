use theta_proto::scheme_types::Group;

use crate::{
    dl_schemes::commitments::{
        interface::{Commitment, CommitmentParams},
        pedersen::PedersenCommitmentParams,
    },
    integers::sizedint::SizedBigInt,
    rand::{RngAlgorithm, RNG},
    scheme_types_impl::GroupDetails,
};

#[test]
fn test_scheme() {
    let group = Group::Bls12381;
    let mut rng = RNG::new(RngAlgorithm::OsRng);

    let x = SizedBigInt::new_rand(&group, &group.get_order(), &mut rng);
    let r = SizedBigInt::new_rand(&group, &group.get_order(), &mut rng);

    let params = CommitmentParams::Pedersen(PedersenCommitmentParams::init(x, r));
    let c = Commitment::commit(&params);

    let result = c.verify(&params);

    assert!(result == true);
}

#[test]
fn test_other_committed_value() {
    let group = Group::Bls12381;
    let mut rng = RNG::new(RngAlgorithm::OsRng);

    let x = SizedBigInt::new_rand(&group, &group.get_order(), &mut rng);
    let r = SizedBigInt::new_rand(&group, &group.get_order(), &mut rng);

    let x_bar = SizedBigInt::new_copy(&x.add(&SizedBigInt::new_int(&group, 1)));
    let r_bar = SizedBigInt::new_copy(&r);

    let params = CommitmentParams::Pedersen(PedersenCommitmentParams::init(x, r));
    let other_params = CommitmentParams::Pedersen(PedersenCommitmentParams::init(x_bar, r_bar));

    let c = Commitment::commit(&params);

    let result = c.verify(&other_params);

    assert!(result == false);
}
