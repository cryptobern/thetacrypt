use crate::groups::ec::{bls12381::Bls12381BIG, bn254::Bn254BIG, ed25519::Ed25519BIG};
use crate::interface::Serializable;
use hex::FromHex;
use mcore::arch::Chunk;
use mcore::bls12381::big::MODBYTES as BLS12381MODBYTES;
use mcore::bn254::big::MODBYTES as BN254MODBYTES;
use mcore::ed25519::big::MODBYTES as ED25519MODBYTES;
use theta_proto::scheme_types::Group;

use crate::rand::RNG;

/// Wrapper for the different fixed size BIG implementations in Miracl Core
/// In Miracl Core, each curve has its own big integer implementation with a
/// fixed amount of bits.
pub trait FixedSizeInt: Sized + Clone + 'static {
    type DataType;

    // creates a new BigImpl initialized to 0
    fn new() -> SizedBigInt;

    // returns a copy of y
    fn new_copy(y: &SizedBigInt) -> SizedBigInt;

    // creates BigImpl from array of chunks
    fn new_ints(a: &[Chunk]) -> SizedBigInt;

    // creates BigImpl from isize
    fn new_int(i: isize) -> SizedBigInt;

    // generate random BigImpl in range [0, q]
    fn new_rand(q: &SizedBigInt, rng: &mut RNG) -> SizedBigInt;

    // converts byte vector to BigImpl and returns it
    fn from_bytes(bytes: &[u8]) -> SizedBigInt;

    // returns self % y
    fn rmod(&self, y: &SizedBigInt) -> SizedBigInt;

    // returns self*y % m
    fn mul_mod(&self, y: &SizedBigInt, m: &SizedBigInt) -> SizedBigInt;

    // returns self^(-1) % m
    fn inv_mod(&self, m: &SizedBigInt) -> SizedBigInt;

    // returns self + y
    fn add(&self, y: &SizedBigInt) -> SizedBigInt;

    // returns self - y
    fn sub(&self, y: &SizedBigInt) -> SizedBigInt;

    // returns self*i
    fn imul(&self, i: isize) -> SizedBigInt;

    // returns x^y % m
    fn pow_mod(&mut self, y: &SizedBigInt, m: &SizedBigInt) -> SizedBigInt;

    // converts self to byte vector
    fn to_bytes(&self) -> Vec<u8>;

    // converts self to a printable hex string
    fn to_string(&self) -> String;

    // compares y to self and returns true if equal
    fn equals(&self, y: &SizedBigInt) -> bool;

    // compares y to self, return 0 if self==y, -1 if self < y, +1 if self > b
    fn cmp(&self, y: &SizedBigInt) -> isize;
}

#[derive(Debug)]
pub enum SizedBigInt {
    Bls12381(Bls12381BIG),
    Bn254(Bn254BIG),
    Ed25519(Ed25519BIG),
}

impl PartialEq for SizedBigInt {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bls12381(l0), Self::Bls12381(r0)) => {
                l0.equals(&SizedBigInt::Bls12381(r0.clone()))
            }
            (Self::Bn254(l0), Self::Bn254(r0)) => l0.equals(&SizedBigInt::Bn254(r0.clone())),
            (Self::Ed25519(l0), Self::Ed25519(r0)) => l0.equals(&SizedBigInt::Ed25519(r0.clone())),
            _ => false,
        }
    }
}

impl SizedBigInt {
    pub fn new(group: &Group) -> SizedBigInt {
        match group {
            Group::Bls12381 => Bls12381BIG::new(),
            Group::Bn254 => Bn254BIG::new(),
            Group::Ed25519 => Ed25519BIG::new(),
            _ => {
                todo!()
            }
        }
    }

    pub fn new_rand(group: &Group, q: &SizedBigInt, rng: &mut RNG) -> SizedBigInt {
        match group {
            Group::Bls12381 => Bls12381BIG::new_rand(q, rng),
            Group::Bn254 => Bn254BIG::new_rand(q, rng),
            Group::Ed25519 => Ed25519BIG::new_rand(q, rng),
            _ => todo!(),
        }
    }

    pub fn new_int(group: &Group, i: isize) -> SizedBigInt {
        match group {
            Group::Bls12381 => Bls12381BIG::new_int(i),
            Group::Bn254 => Bn254BIG::new_int(i),
            Group::Ed25519 => Ed25519BIG::new_int(i),
            _ => todo!(),
        }
    }

    pub fn new_copy(x: &SizedBigInt) -> SizedBigInt {
        x.clone()
    }

    pub fn from_bytes(group: &Group, bytes: &[u8]) -> SizedBigInt {
        match group {
            Group::Bls12381 => Bls12381BIG::from_bytes(bytes),
            Group::Bn254 => Bn254BIG::from_bytes(bytes),
            Group::Ed25519 => Ed25519BIG::from_bytes(bytes),
            _ => todo!(),
        }
    }

    pub fn from_hex(group: &Group, hex: &str) -> SizedBigInt {
        let bytes: Vec<u8> = Vec::from_hex(hex).expect("Invalid Hex String");

        SizedBigInt::from_bytes(group, &bytes)
    }

    pub fn rmul(x: &SizedBigInt, y: &SizedBigInt, q: &SizedBigInt) -> SizedBigInt {
        x.mul_mod(&y, &q)
    }

    pub fn rmod(&self, y: &SizedBigInt) -> SizedBigInt {
        match self {
            SizedBigInt::Bls12381(x) => x.rmod(y),
            SizedBigInt::Bn254(x) => x.rmod(y),
            SizedBigInt::Ed25519(x) => x.rmod(y),
        }
    }

    pub fn mul_mod(&self, y: &SizedBigInt, m: &SizedBigInt) -> SizedBigInt {
        match self {
            SizedBigInt::Bls12381(x) => x.mul_mod(y, m),
            SizedBigInt::Bn254(x) => x.mul_mod(y, m),
            SizedBigInt::Ed25519(x) => x.mul_mod(y, m),
        }
    }

    pub fn add(&self, y: &SizedBigInt) -> SizedBigInt {
        match self {
            SizedBigInt::Bls12381(x) => x.add(y),
            SizedBigInt::Bn254(x) => x.add(y),
            SizedBigInt::Ed25519(x) => x.add(y),
        }
    }

    pub fn sub(&self, y: &SizedBigInt) -> SizedBigInt {
        match self {
            SizedBigInt::Bls12381(x) => x.sub(y),
            SizedBigInt::Bn254(x) => x.sub(y),
            SizedBigInt::Ed25519(x) => x.sub(y),
        }
    }

    pub fn inv_mod(&self, m: &SizedBigInt) -> SizedBigInt {
        match self {
            SizedBigInt::Bls12381(x) => x.inv_mod(m),
            SizedBigInt::Bn254(x) => x.inv_mod(m),
            SizedBigInt::Ed25519(x) => x.inv_mod(m),
        }
    }

    pub fn imul(&self, i: isize) -> SizedBigInt {
        match self {
            SizedBigInt::Bls12381(x) => x.imul(i),
            SizedBigInt::Bn254(x) => x.imul(i),
            SizedBigInt::Ed25519(x) => x.imul(i),
        }
    }

    pub fn pow_mod(&mut self, y: &SizedBigInt, m: &SizedBigInt) -> SizedBigInt {
        match self {
            SizedBigInt::Bls12381(x) => x.pow_mod(y, m),
            SizedBigInt::Bn254(x) => x.pow_mod(y, m),
            SizedBigInt::Ed25519(x) => x.pow_mod(y, m),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SizedBigInt::Bls12381(x) => x.to_bytes(),
            SizedBigInt::Bn254(x) => x.to_bytes(),
            SizedBigInt::Ed25519(x) => x.to_bytes(),
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            SizedBigInt::Bls12381(x) => x.to_string(),
            SizedBigInt::Bn254(x) => x.to_string(),
            SizedBigInt::Ed25519(x) => x.to_string(),
        }
    }

    pub fn nbytes(&self) -> usize {
        match self {
            SizedBigInt::Bls12381(_) => BLS12381MODBYTES,
            SizedBigInt::Bn254(_) => BN254MODBYTES,
            SizedBigInt::Ed25519(_) => ED25519MODBYTES,
        }
    }

    pub fn equals(&self, y: &SizedBigInt) -> bool {
        match self {
            SizedBigInt::Bls12381(x) => x.equals(y),
            SizedBigInt::Bn254(x) => x.equals(y),
            SizedBigInt::Ed25519(x) => x.equals(y),
        }
    }

    pub fn get_group(&self) -> &Group {
        match self {
            SizedBigInt::Bls12381(_x) => &Group::Bls12381,
            SizedBigInt::Bn254(_x) => &Group::Bn254,
            SizedBigInt::Ed25519(_x) => &Group::Ed25519,
        }
    }

    pub fn cmp(&self, y: &Self) -> isize {
        match self {
            SizedBigInt::Bls12381(_x) => _x.cmp(y),
            SizedBigInt::Bn254(_x) => _x.cmp(y),
            SizedBigInt::Ed25519(_x) => _x.cmp(y),
        }
    }
}

impl Clone for SizedBigInt {
    fn clone(&self) -> Self {
        match self {
            SizedBigInt::Bls12381(x) => SizedBigInt::Bls12381(x.clone()),
            SizedBigInt::Bn254(x) => SizedBigInt::Bn254(x.clone()),
            SizedBigInt::Ed25519(x) => SizedBigInt::Ed25519(x.clone()),
        }
    }
}
