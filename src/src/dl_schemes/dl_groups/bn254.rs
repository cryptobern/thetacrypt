use std::mem::ManuallyDrop;

use derive::{Serializable, EcPairingGroupImpl, BigIntegerImpl};
use mcore::{bn254::{big::{BIG, MODBYTES}, ecp::{ECP}, ecp2::ECP2, fp12::FP12, pair, rom}};
use rasn::{AsnType, Decode, Encode, Encoder};
use crate::{dl_schemes::bigint::BigInt, rand::RNG, interface::ThresholdCryptoError, proto::scheme_types::Group, proto::scheme_types::ThresholdScheme};
use crate::dl_schemes::bigint::*;

use crate::group::{GroupElement};

#[repr(C)]
union ECPoint {
    ecp: ManuallyDrop<ECP>,
    ecp2: ManuallyDrop<ECP2>,
    fp12: ManuallyDrop<FP12>
}

impl std::fmt::Debug for ECPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<ECPoint>")
    }
}

#[derive(Debug, EcPairingGroupImpl)]
pub struct Bn254 {
    i:u8,           /* i indicates whether element is ECP, ECP2 or FP12 */
    value: ECPoint
}

#[derive(Debug, AsnType, Serializable, BigIntegerImpl)]
pub struct Bn254BIG {
    value: BIG
}