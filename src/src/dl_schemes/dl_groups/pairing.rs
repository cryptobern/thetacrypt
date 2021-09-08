use der::asn1::Null;
use mcore::rand::RAND;

use crate::{bigint::BigInt, dl_schemes::dl_groups::dl_group::*};

use super::{BigImpl, bls12381::Bls12381, ed25519::Ed25519};

pub trait PairingEngine:
    DlGroup {
    type G2: DlGroup;
    type G3: DlGroup;

    fn pair(g1: &Self::G2, g2: &Self) -> Self::G3;

    fn ddh(g1: &Self::G2, g2: &Self, g3:&Self::G2, g4:&Self) -> bool;
}