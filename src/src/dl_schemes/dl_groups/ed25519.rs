use derive::{Serializable, EcGroupImpl, BigIntegerImpl};
use mcore::{ed25519::{big::{BIG, MODBYTES}, ecp::ECP, rom}};
use rasn::{AsnType, Encode, Decode, Encoder, types::BitString};
use crate::{dl_schemes::bigint::BigInt, rand::RNG};
use crate::group::{Group, GroupElement};
use crate::dl_schemes::bigint::*;

#[derive(AsnType, Debug, EcGroupImpl)]
pub struct Ed25519 {
    value: ECP
}

#[derive(AsnType, Debug, Serializable, BigIntegerImpl)]
pub struct Ed25519BIG {
    value: BIG
}