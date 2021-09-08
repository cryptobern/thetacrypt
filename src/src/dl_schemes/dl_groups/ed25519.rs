use std::fmt::Display;

use mcore::{ed25519::{big::{BIG, MODBYTES}, dbig::DBIG, ecp::ECP, rom}, rand::RAND};
use crate::{bigint::BigInt, dl_schemes::{DlDomain, dl_groups::dl_group::*}};

use super::{BigImpl, pairing::PairingEngine};
pub struct Ed25519 {
    value: ECP
}

impl PairingEngine for Ed25519 {
    type G2 = Self;

    type G3 = Self;

    fn pair(g1: &Self::G2, g2: &Self) -> Self::G3 {
        panic!("Ed22519 does not support pairings!")
    }

    fn ddh(g1: &Self::G2, g2: &Self, g3:&Self::G2, g4:&Self) -> bool {
        panic!("Ed22519 does not support pairings!")
    }
}

impl DlDomain for Ed25519 {
    fn is_pairing_friendly() -> bool {
        false
    }
}

impl DlGroup for Ed25519 {
    type BigInt = Ed25519BIG;
    type DataType = ECP;

    fn new() -> Self {
        Self { value:ECP::generator() }
    }
    
    fn new_pow_big (x: &BigImpl) -> Self {
        if let BigImpl::Ed25519(v) = x {
            Self { value:ECP::generator().mul(&v.value)}
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn new_rand(rng: &mut impl mcore::rand::RAND) -> Self {
        Self::new_pow_big(&BigImpl::Ed25519(Self::BigInt { value:BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng) }))
    }

    fn new_copy(g: &Self) -> Self {
        Self { value:g.value.clone() }
    }

    fn mul(&mut self, g: &Self) {
        self.value.add(&g.value);
    }

    fn pow (&mut self, x: &BigImpl) {
        if let BigImpl::Ed25519(v) = x {
            self.value = self.value.mul(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn div(&mut self, g: &Self) {
        self.value.sub(&g.value);
    }

    fn set(&mut self, g: &Self::DataType) {
        self.value = g.clone()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf:Vec<u8> = vec![0;2*MODBYTES + 1];
        self.value.tobytes(&mut buf, true);
        buf
    }

    fn from_bytes(&self, bytes: &[u8]) {
        ECP::frombytes(bytes);
    }

    fn equals(&self, g: &Self) -> bool {
        self.value.equals(&g.value)
    }

    fn get_order() -> BigImpl {
        Self::BigInt::new_ints(&rom::CURVE_ORDER)
    }

    fn wrp(x: &Self::BigInt) -> BigImpl {
        BigImpl::Ed25519(x.clone())    
    }

    fn nbytes() -> usize {
        2*MODBYTES 
    }

    fn to_string(&self) -> String {
        self.value.tostring()
    }
}

pub struct Ed25519BIG {
    value: BIG
}

impl BigInt for Ed25519BIG {
    type DataType = BIG;

    fn new() -> BigImpl {
        BigImpl::Ed25519(Self { value: BIG::new() })
    }

    fn new_big(y: &BigImpl) -> BigImpl {
        if let BigImpl::Ed25519(v) = y {
            BigImpl::Ed25519(Self { value: BIG::new_big(&v.value)})
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn new_copy(y: &BigImpl) -> BigImpl {
        if let BigImpl::Ed25519(v) = y {
            BigImpl::Ed25519(Self { value:BIG::new_copy(&v.value) })
        } else {
            panic!("Incompatible big integer implementation!");
        }
        
    }

    fn new_ints(a: &[mcore::arch::Chunk]) -> BigImpl {
        BigImpl::Ed25519(Self { value:BIG::new_ints(a) })
    }

    fn new_int(i: isize) -> BigImpl {
        BigImpl::Ed25519(Self { value:BIG::new_int(i) })
    }

    fn new_rand(q: &BigImpl, rng: &mut impl RAND) -> BigImpl {
        if let BigImpl::Ed25519(v) = q {
            BigImpl::Ed25519(Self { value:BIG::randomnum(&v.value, rng) })
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn from_bytes(bytes: &[u8]) -> BigImpl {
        BigImpl::Ed25519(Self { value:BIG::frombytes(bytes)})
    }

    fn rmod(&mut self, y: &BigImpl) {
        if let BigImpl::Ed25519(v) = y {
            self.value.rmod(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn mul_mod(&mut self, y: &BigImpl, m: &BigImpl) {
        if let (BigImpl::Ed25519(v), BigImpl::Ed25519(w)) = (y, m) {
            self.value = BIG::mul(&self.value, &v.value).dmod(&w.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
        
    }

    fn add(&mut self, y: &BigImpl) {
        if let BigImpl::Ed25519(v) = y {
            self.value.add(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut b:Vec<u8> = vec![0; MODBYTES];
        self.value.tobytes(&mut b);
        b
    }

    fn to_string(&self) -> String {
        self.value.tostring()
    }

    fn pow_mod(&mut self, y: &BigImpl, m: &BigImpl) {
        if let (BigImpl::Ed25519(v), BigImpl::Ed25519(w)) = (y, m) {
            self.value = self.value.powmod(&v.value, &w.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn inv_mod(&mut self, m: &BigImpl) {
        if let BigImpl::Ed25519(v) = m {
            self.value.invmodp(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }   
    }

    fn sub(&mut self, y: &BigImpl) {
        if let BigImpl::Ed25519(v) = y {
            self.value.sub(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }  
    }

    fn imul(&mut self, i: isize) {
        self.value.imul(i);
    }

    fn equals(&self, y: &BigImpl) -> bool {
        if let BigImpl::Ed25519(v) = y {
            BIG::comp(&self.value, &v.value) == 0
        } else {
            false
        }  
    }
}

impl Clone for Ed25519BIG {
    fn clone(&self) -> Self {
        Self{ value: self.value.clone() }
    }
}

impl Clone for Ed25519 {
    fn clone(&self) -> Self {
        Self{ value: self.value.clone() }
    }
}