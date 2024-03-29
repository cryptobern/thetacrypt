use derive::{EcGroupImpl, BigIntegerImpl};
use mcore::{ed25519::{big::{BIG, MODBYTES}, ecp::ECP, rom}};
use rasn::{AsnType, Decode, Encode, Encoder};
use crate::{ rand::RNG};
use crate::group::{ GroupElement};
use theta_proto::scheme_types::{Group, ThresholdScheme}; 
use crate::dl_schemes::bigint::{BigInt, BigImpl};

#[derive(AsnType, Debug, EcGroupImpl)]
pub struct Ed25519 {
    value: ECP
}

#[derive(AsnType, Debug, BigIntegerImpl)]
pub struct Ed25519BIG {
    value: BIG
}