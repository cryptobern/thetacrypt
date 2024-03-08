use crate::groups::group::GroupElement;
use crate::integers::sizedint::{FixedSizeInt, SizedBigInt};
use crate::rand::RNG;
use mcore::ed25519::{
    big::{BIG, MODBYTES},
    ecp::ECP,
    rom,
};
use rasn::{AsnType, Decode, Encode, Encoder};
use theta_derive::{BigIntegerImpl, EcGroupImpl};
use theta_proto::scheme_types::{Group, ThresholdScheme};

#[derive(AsnType, Debug, EcGroupImpl)]
pub struct Ed25519 {
    value: ECP,
}

#[derive(AsnType, Debug, BigIntegerImpl)]
pub struct Ed25519BIG {
    value: BIG,
}
