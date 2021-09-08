use mcore::{arch::Chunk, bls12381::big::BIG as Bls12381B, bn254::big::BIG as Bn254B, ed25519::big::BIG as Ed25519B, rand::RAND};

pub mod bls12381;
pub mod bn254;
pub mod ed25519;
pub mod dl_group;
pub mod pairing;

use crate::{bigint::BigInt, dl_schemes::dl_groups::bn254::Bn254};

use self::{bls12381::{Bls12381, Bls12381BIG}, bn254::Bn254BIG, ed25519::Ed25519BIG, pairing::PairingEngine};

pub enum BigImpl {
    Bls12381(Bls12381BIG),
    Bn254(Bn254BIG),
    Ed25519(Ed25519BIG)
}

impl BigImpl {
    pub fn rmul(x: &BigImpl, y: &BigImpl, q: &BigImpl) -> BigImpl {
        let mut z = x.clone();
        z.mul_mod(&y, &q);
        z
    }

    pub fn rmod(&mut self, y: &BigImpl) {
        match self {
            BigImpl::Bls12381(x) => x.rmod(y),
            BigImpl::Bn254(x) => x.rmod(y),
            BigImpl::Ed25519(x) => x.rmod(y)
        }
    }

    pub fn mul_mod(&mut self, y: &BigImpl, m: &BigImpl) {
        match self {
             BigImpl::Bls12381(x) => x.mul_mod(y, m),
             BigImpl::Bn254(x) => x.mul_mod(y, m),
             BigImpl::Ed25519(x) => x.mul_mod(y, m)
        }
    }

    pub fn add(&mut self, y: &BigImpl) {
        match self {
             BigImpl::Bls12381(x) => x.add(y),
             BigImpl::Bn254(x) => x.add(y),
             BigImpl::Ed25519(x) => x.add(y)
        }
    }

    pub fn pow_mod(&mut self, y: &BigImpl, m: &BigImpl) {
        match self {
             BigImpl::Bls12381(x) => x.pow_mod(y, m),
             BigImpl::Bn254(x) => x.pow_mod(y, m),
             BigImpl::Ed25519(x) => x.pow_mod(y, m)
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            BigImpl::Bls12381(x) => x.to_bytes(),
            BigImpl::Bn254(x) => x.to_bytes(),
            BigImpl::Ed25519(x) => x.to_bytes()
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            BigImpl::Bls12381(x) => x.to_string(),
            BigImpl::Bn254(x) => x.to_string(),
            BigImpl::Ed25519(x) => x.to_string()
        }
    }
}

impl Clone for BigImpl {
    fn clone(&self) -> Self {
        match self {
            BigImpl::Bls12381(x) => BigImpl::Bls12381(x.clone()),
            BigImpl::Bn254(x) => BigImpl::Bn254(x.clone()),
            BigImpl::Ed25519(x) => BigImpl::Ed25519(x.clone()),
        }
    }
}