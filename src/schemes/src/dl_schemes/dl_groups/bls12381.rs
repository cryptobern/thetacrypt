use std::mem::ManuallyDrop;

use derive::{ EcPairingGroupImpl, BigIntegerImpl};
use mcore::{bls12381::{big::{BIG, MODBYTES}, ecp::{ECP}, ecp2::ECP2, fp12::FP12, pair, rom}};
use rasn::{AsnType, Decode, Encode, Encoder};
use crate::{rand::RNG, interface::ThresholdCryptoError};
use crate::dl_schemes::bigint::{BigInt, BigImpl};
use crate::group::{GroupElement};
use crate::interface::ThresholdScheme; 
use crate::group::Group;

#[repr(C)]
union ECPoint {
    ecp: ManuallyDrop<ECP>,
    ecp2: ManuallyDrop<ECP2>,
    fp12: ManuallyDrop<FP12>,
}

impl std::fmt::Debug for ECPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<ECPoint>")
    }
}

#[derive(Debug, EcPairingGroupImpl)]
pub struct Bls12381 {
    i:u8,           /* i indicates whether element is ECP, ECP2 or FP12 */
    value: ECPoint
}

#[derive(Debug, BigIntegerImpl)]
pub struct Bls12381BIG {
    value: BIG
}