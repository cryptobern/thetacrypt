use mcore::{arch::Chunk};
use mcore::bls12381::big::MODBYTES as BLS12381MODBYTES;
use mcore::ed25519::big::MODBYTES as ED25519MODBYTES;
use mcore::bn254::big::MODBYTES as BN254MODBYTES;
use rasn::AsnType;
use crate::dl_schemes::dl_groups::{bls12381::{Bls12381BIG}, bn254::Bn254BIG, ed25519::Ed25519BIG};
use crate::interface::Serializable;
use crate::rand::RNG;

/// Wrapper for the different BIG implementations in Miracl Core
pub trait BigInt: 
    Sized 
    + Serializable
    + Clone
    + 'static {
    type DataType;

    fn new() -> BigImpl;
    fn new_big(y: &BigImpl) -> BigImpl;
    fn new_ints(a: &[Chunk]) -> BigImpl;
    fn new_int(i: isize) -> BigImpl;
    fn new_copy(y: &BigImpl) -> BigImpl;
    fn new_rand(q: &BigImpl, rng: &mut RNG) -> BigImpl;
    fn from_bytes(bytes: &[u8]) -> BigImpl;
    fn rmod(&mut self, y: &BigImpl);
    fn mul_mod(&mut self, y: &BigImpl, m: &BigImpl);
    fn inv_mod(&mut self, m: &BigImpl);
    fn add(&mut self, y: &BigImpl);
    fn sub(&mut self, y: &BigImpl);
    fn imul(&mut self, i: isize);
    fn pow_mod(&mut self, y: &BigImpl, m: &BigImpl);
    fn to_bytes(&self) -> Vec<u8>;
    fn to_string(&self) -> String;
    fn equals(&self, y: &BigImpl) -> bool;
}

#[derive(Debug)]
pub enum BigImpl {
    Bls12381(Bls12381BIG),
    Bn254(Bn254BIG),
    Ed25519(Ed25519BIG)
}

impl PartialEq for BigImpl{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bls12381(l0), Self::Bls12381(r0)) => l0.equals(&BigImpl::Bls12381(r0.clone())),
            (Self::Bn254(l0), Self::Bn254(r0)) => l0.equals(&BigImpl::Bn254(r0.clone())),
            (Self::Ed25519(l0), Self::Ed25519(r0)) => l0.equals(&BigImpl::Ed25519(r0.clone())),
            _ => false
        }
    }
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

    pub fn sub(&mut self, y: &BigImpl) {
        match self {
             BigImpl::Bls12381(x) => x.sub(y),
             BigImpl::Bn254(x) => x.sub(y),
             BigImpl::Ed25519(x) => x.sub(y)
        }
    }

    pub fn inv_mod(&mut self, m: &BigImpl) {
        match self {
             BigImpl::Bls12381(x) => x.inv_mod(m),
             BigImpl::Bn254(x) => x.inv_mod(m),
             BigImpl::Ed25519(x) => x.inv_mod(m),
        }
    }

    pub fn imul(&mut self, i: isize) {
        match self {
             BigImpl::Bls12381(x) => x.imul(i),
             BigImpl::Bn254(x) => x.imul(i),
             BigImpl::Ed25519(x) => x.imul(i),
        }
    }

    pub fn pow_mod(&mut self, y: &BigImpl, m: &BigImpl) {
        match self {
             BigImpl::Bls12381(x) => x.pow_mod(y, m),
             BigImpl::Bn254(x) => x.pow_mod(y, m),
             BigImpl::Ed25519(x) => x.pow_mod(y, m),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            BigImpl::Bls12381(x) => x.to_bytes(),
            BigImpl::Bn254(x) => x.to_bytes(),
            BigImpl::Ed25519(x) => x.to_bytes(),
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            BigImpl::Bls12381(x) => x.to_string(),
            BigImpl::Bn254(x) => x.to_string(),
            BigImpl::Ed25519(x) => x.to_string(),
        }
    }

    pub fn nbytes(&self) -> usize {
        match self {
            BigImpl::Bls12381(_) => BLS12381MODBYTES,
            BigImpl::Bn254(_) => BN254MODBYTES,
            BigImpl::Ed25519(_) => ED25519MODBYTES,
        }
    }

    pub fn equals(&self, y: &BigImpl) -> bool {
        match self {
            BigImpl::Bls12381(x) => x.equals(y),
            BigImpl::Bn254(x) => x.equals(y),
            BigImpl::Ed25519(x) => x.equals(y),
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