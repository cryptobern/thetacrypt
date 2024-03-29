use std::mem::ManuallyDrop;

use hex::FromHex;
use theta_proto::scheme_types::Group;
use mcore::{arch::Chunk};
use mcore::bls12381::big::MODBYTES as BLS12381MODBYTES;
use mcore::ed25519::big::MODBYTES as ED25519MODBYTES;
use mcore::bn254::big::MODBYTES as BN254MODBYTES;
use crate::dl_schemes::dl_groups::{bls12381::{Bls12381BIG}, bn254::Bn254BIG, ed25519::Ed25519BIG};
use crate::interface::Serializable;

use crate::rand::RNG;

use crate::group::{GroupElement};

/// Wrapper for the different BIG implementations in Miracl Core
pub trait BigInt: 
    Sized 
    + Clone
    + 'static {
    type DataType;

    // creates a new BigImpl initialized to 0
    fn new() -> BigImpl;

    // returns a copy of y
    fn new_copy(y: &BigImpl) -> BigImpl;

    // creates BigImpl from array of chunks
    fn new_ints(a: &[Chunk]) -> BigImpl;

    // creates BigImpl from isize
    fn new_int(i: isize) -> BigImpl;

    // generate random BigImpl in range [0, q]
    fn new_rand(q: &BigImpl, rng: &mut RNG) -> BigImpl;

    // converts byte vector to BigImpl and returns it
    fn from_bytes(bytes: &[u8]) -> BigImpl;

    // returns self % y
    fn rmod(&self, y: &BigImpl) -> BigImpl;

    // returns self*y % m
    fn mul_mod(&self, y: &BigImpl, m: &BigImpl) -> BigImpl;

    // returns self^(-1) % m
    fn inv_mod(&self, m: &BigImpl) -> BigImpl;

    // returns self + y
    fn add(&self, y: &BigImpl) -> BigImpl;

    // returns self - y
    fn sub(&self, y: &BigImpl) -> BigImpl;

    // returns self*i
    fn imul(&self, i: isize) -> BigImpl;

    // returns x^y % m
    fn pow_mod(&mut self, y: &BigImpl, m: &BigImpl) -> BigImpl;
    
    // converts self to byte vector
    fn to_bytes(&self) -> Vec<u8>;

    // converts self to a printable hex string
    fn to_string(&self) -> String;

    // compares y to self and returns true if equal
    fn equals(&self, y: &BigImpl) -> bool;

    // compares y to self, return 0 if self==y, -1 if self < y, +1 if self > b
    fn cmp(&self, y: &BigImpl) -> isize;
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
    pub fn new(group: &Group) -> BigImpl {
        match group {
            Group::Bls12381 => {
                Bls12381BIG::new()
            },
            Group::Bn254 => {
                Bn254BIG::new()
            },
            Group::Ed25519 => {
                Ed25519BIG::new()
            },
            _ => {
                todo!()
            }
        }
    }

    pub fn new_rand(group: &Group, q: &BigImpl, rng: &mut RNG) -> BigImpl {
        match group {
            Group::Bls12381 => {
                Bls12381BIG::new_rand(q, rng)
            },
            Group::Bn254 => {
                Bn254BIG::new_rand(q, rng)
            },
            Group::Ed25519 => {
                Ed25519BIG::new_rand(q, rng)
            },
            _ => todo!()
        }
    }

    pub fn new_int(group: &Group, i: isize) -> BigImpl {
        match group {
            Group::Bls12381 => {
                Bls12381BIG::new_int(i)
            },
            Group::Bn254 => {
                Bn254BIG::new_int(i)
            },
            Group::Ed25519 => {
                Ed25519BIG::new_int(i)
            },
            _ => todo!()
        }
    }

    pub fn new_copy(x: &BigImpl) -> BigImpl {
        x.clone()
    }

    pub fn from_bytes(group: &Group, bytes: &[u8]) -> BigImpl {
        match group {
            Group::Bls12381 => {
                Bls12381BIG::from_bytes(bytes)
            },
            Group::Bn254 => {
                Bn254BIG::from_bytes(bytes)
            },
            Group::Ed25519 => {
                Ed25519BIG::from_bytes(bytes)
            },
            _ => todo!()
        }
    }

    pub fn from_hex(group: &Group, hex: &str) -> BigImpl {
        let bytes: Vec<u8> = Vec::from_hex(hex).expect("Invalid Hex String");

        BigImpl::from_bytes(group, &bytes)
    }

    pub fn rmul(x: &BigImpl, y: &BigImpl, q: &BigImpl) -> BigImpl {
        x.mul_mod(&y, &q)
    }

    pub fn rmod(&self, y: &BigImpl) -> BigImpl {
        match self {
            BigImpl::Bls12381(x) => x.rmod(y),
            BigImpl::Bn254(x) => x.rmod(y),
            BigImpl::Ed25519(x) => x.rmod(y)
        }
    }

    pub fn mul_mod(&self, y: &BigImpl, m: &BigImpl) -> BigImpl {
        match self {
             BigImpl::Bls12381(x) => x.mul_mod(y, m),
             BigImpl::Bn254(x) => x.mul_mod(y, m),
             BigImpl::Ed25519(x) => x.mul_mod(y, m)
        }
    }

    pub fn add(&self, y: &BigImpl) -> BigImpl {
        match self {
             BigImpl::Bls12381(x) => x.add(y),
             BigImpl::Bn254(x) => x.add(y),
             BigImpl::Ed25519(x) => x.add(y)
        }
    }

    pub fn sub(&self, y: &BigImpl) -> BigImpl {
        match self {
             BigImpl::Bls12381(x) => x.sub(y),
             BigImpl::Bn254(x) => x.sub(y),
             BigImpl::Ed25519(x) => x.sub(y)
        }
    }

    pub fn inv_mod(&self, m: &BigImpl) -> BigImpl {
        match self {
             BigImpl::Bls12381(x) => x.inv_mod(m),
             BigImpl::Bn254(x) => x.inv_mod(m),
             BigImpl::Ed25519(x) => x.inv_mod(m),
        }
    }

    pub fn imul(&self, i: isize) -> BigImpl {
        match self {
             BigImpl::Bls12381(x) => x.imul(i),
             BigImpl::Bn254(x) => x.imul(i),
             BigImpl::Ed25519(x) => x.imul(i),
        }
    }

    pub fn pow_mod(&mut self, y: &BigImpl, m: &BigImpl) -> BigImpl {
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

    pub fn get_group(&self) -> &Group {
        match self {
            BigImpl::Bls12381(_x) => &Group::Bls12381,
            BigImpl::Bn254(_x) => &Group::Bn254,
            BigImpl::Ed25519(_x) => &Group::Ed25519,
       }
    }

    pub fn cmp(&self, y: &Self) -> isize {
        match self {
            BigImpl::Bls12381(_x) => _x.cmp(y),
            BigImpl::Bn254(_x) => _x.cmp(y),
            BigImpl::Ed25519(_x) => _x.cmp(y),
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