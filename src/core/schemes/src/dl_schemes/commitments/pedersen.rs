use crate::groups::group::GroupElement;
use crate::integers::sizedint::SizedBigInt;
use crate::scheme_types_impl::GroupDetails;

use crate::groups::group::GroupOperations;
pub struct PedersenCommitmentParams {
    pub x: SizedBigInt,
    pub r: SizedBigInt,
}

impl PedersenCommitmentParams {
    pub fn init(x: SizedBigInt, r: SizedBigInt) -> PedersenCommitmentParams {
        PedersenCommitmentParams { x: x, r: r }
    }
}

pub struct PedersenCommitment {
    c: GroupElement,
}

impl PedersenCommitment {
    pub fn commit(params: &PedersenCommitmentParams) -> Self {
        let group = params.x.get_group();
        let gx = GroupElement::new_pow_big(&group, &params.x);
        let hr = &group.get_alternate_generator().pow(&params.r);
        return PedersenCommitment { c: gx.mul(&hr) };
    }

    pub fn verify(self, params: &PedersenCommitmentParams) -> bool {
        let group = params.x.get_group();
        let gx = GroupElement::new_pow_big(&group, &params.x);
        let hr = &group.get_alternate_generator().pow(&params.r);
        return self.c.eq(&gx.mul(&hr));
    }
}
