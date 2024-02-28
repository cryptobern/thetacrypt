use crate::dl_schemes::bigint::{FixedSizeInt, SizedBigInt};
use crate::group::GroupElement;
use crate::rand::RNG;
use derive::{BigIntegerImpl, EcGroupImpl};
use mcore::ed25519::{
    big::{BIG, MODBYTES},
    ecp::ECP,
    rom,
};
use rasn::{AsnType, Decode, Encode, Encoder};
use theta_proto::scheme_types::{Group, ThresholdScheme};

#[derive(AsnType, Debug, EcGroupImpl)]
pub struct Ed25519 {
    value: ECP,
}

#[derive(AsnType, Debug, BigIntegerImpl)]
pub struct Ed25519BIG {
    value: BIG,
}
