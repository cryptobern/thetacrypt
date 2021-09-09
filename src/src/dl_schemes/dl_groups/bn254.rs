use mcore::{bn254::{big::{BIG, MODBYTES}, ecp::ECP, ecp2::ECP2, fp12::FP12, pair, rom}, rand::RAND};
use crate::{bigint::BigInt, dl_schemes::{DlDomain, dl_groups::dl_group::*}};
use crate::dl_schemes::dl_groups::pairing::*;

use super::BigImpl;

pub struct Bn254 {
    value: ECP
}

impl PairingEngine for Bn254 {
    type G2 = Bn254ECP2;
    type G3 = Bn254FP12;

    fn pair(g1: &Self::G2, g2: &Self) -> Self::G3 {
        let rhs = pair::ate(&g1.value, &g2.value);
        pair::fexp(&rhs);
        Self::G3 { value: rhs} 
    }

    fn ddh(g1: &Self::G2, g2: &Self, g3:&Self::G2, g4:&Self) -> bool {
        Self::pair(g1, g2).equals(&Self::pair(g3, g4))
    }
}

impl DlDomain for Bn254 {
    fn is_pairing_friendly() -> bool {
        true
    }
}

impl DlGroup for Bn254 {
    type BigInt = Bn254BIG;
    type DataType = ECP;

    fn new() -> Self {
        Self { value:ECP::generator() }
    }
    
    fn new_pow_big (x: &BigImpl) -> Self {
        if let BigImpl::Bn254(v) = x {
            Self { value:ECP::generator().mul(&v.value)}
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn new_rand(rng: &mut impl mcore::rand::RAND) -> Self {
        Self::new_pow_big(&BigImpl::Bn254(Self::BigInt { value:BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng) }))
    }

    fn new_copy(g: &Self) -> Self {
        Self { value:g.value.clone() }
    }

    fn mul(&mut self, g: &Self) {
        self.value.add(&g.value);
    }

    fn pow (&mut self, x: &BigImpl) {
        if let BigImpl::Bn254(v) = x {
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
        BigImpl::Bn254(x.clone())    
    }

    fn nbytes() -> usize {
        2*MODBYTES 
    }

    fn to_string(&self) -> String {
        self.value.tostring()
    }
}

pub struct Bn254ECP2 {
    value: ECP2
}

impl DlGroup for Bn254ECP2 {
    type BigInt = Bn254BIG;
    type DataType = ECP2;

    fn new() -> Self {
        Self { value:ECP2::generator() }
    }
    
    fn new_pow_big (x: &BigImpl) -> Self {
        if let BigImpl::Bn254(v) = x {
            Self { value:ECP2::generator().mul(&v.value)}
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn new_rand(rng: &mut impl mcore::rand::RAND) -> Self {
        Self::new_pow_big(&BigImpl::Bn254(Self::BigInt { value:BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng) }))
    }

    fn new_copy(g: &Self) -> Self {
        Self { value:g.value.clone() }
    }

    fn mul(&mut self, g: &Self) {
        self.value.add(&g.value);
    }

    fn pow (&mut self, x: &BigImpl) {
        if let BigImpl::Bn254(v) = x {
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
        BigImpl::Bn254(x.clone())    
    }

    fn nbytes() -> usize {
        2*MODBYTES 
    }

    fn to_string(&self) -> String {
        self.value.tostring()
    }
}

pub struct Bn254FP12 {
    value: FP12
}

impl DlGroup for Bn254FP12 {
    type BigInt = Bn254BIG;
    type DataType = FP12;

    fn new() -> Self {
        Self { value:FP12::new() }
    }
    
    fn new_pow_big (x: &BigImpl) -> Self {
        if let BigImpl::Bn254(v) = x {
            Self { value:FP12::new().pow(&v.value)}
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn new_rand(rng: &mut impl mcore::rand::RAND) -> Self {
        Self::new_pow_big(&BigImpl::Bn254(Self::BigInt { value:BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng) }))
    }

    fn new_copy(g: &Self) -> Self {
        Self { value:g.value.clone() }
    }

    fn mul(&mut self, g: &Self) {
        self.value.mul(&g.value);
    }

    fn pow (&mut self, x: &BigImpl) {
        if let BigImpl::Bn254(v) = x {
            self.value = self.value.pow(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn div(&mut self, g: &Self) {
        let mut b = g.value.clone();
        b.inverse();

        self.value.mul(&b);
    }

    fn set(&mut self, g: &Self::DataType) {
        self.value = g.clone()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf:Vec<u8> = vec![0;2 * MODBYTES + 1];
        let mut val = self.value.clone();
        val.tobytes(&mut buf);
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
        BigImpl::Bn254(x.clone())    
    }

    fn nbytes() -> usize {
        MODBYTES 
    }

    fn to_string(&self) -> String {
        self.value.tostring()
    }
}

impl Clone for Bn254FP12 {
    fn clone(&self) -> Self {
        Self{ value: self.value.clone() }
    }
}

impl Clone for Bn254 {
    fn clone(&self) -> Self {
        Self{ value: self.value.clone() }
    }
}

impl Clone for Bn254ECP2 {
    fn clone(&self) -> Self {
        Self{ value: self.value.clone() }
    }
}

pub struct Bn254BIG {
    value: BIG
}

impl BigInt for Bn254BIG {
    type DataType = BIG;

    fn new() -> BigImpl {
        BigImpl::Bn254(Self { value: BIG::new() })
    }

    fn new_big(y: &BigImpl) -> BigImpl {
        if let BigImpl::Bn254(v) = y {
            BigImpl::Bn254(Self { value: BIG::new_big(&v.value)})
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn new_copy(y: &BigImpl) -> BigImpl {
        if let BigImpl::Bn254(v) = y {
            BigImpl::Bn254(Self { value:BIG::new_copy(&v.value) })
        } else {
            panic!("Incompatible big integer implementation!");
        }
        
    }

    fn new_ints(a: &[mcore::arch::Chunk]) -> BigImpl {
        BigImpl::Bn254(Self { value:BIG::new_ints(a) })
    }

    fn new_int(i: isize) -> BigImpl {
        BigImpl::Bn254(Self { value:BIG::new_int(i) })
    }

    fn new_rand(q: &BigImpl, rng: &mut impl RAND) -> BigImpl {
        if let BigImpl::Bn254(v) = q {
            BigImpl::Bn254(Self { value:BIG::randomnum(&v.value, rng) })
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn from_bytes(bytes: &[u8]) -> BigImpl {
        BigImpl::Bn254(Self { value:BIG::frombytes(bytes)})
    }

    fn rmod(&mut self, y: &BigImpl) {
        if let BigImpl::Bn254(v) = y {
            self.value.rmod(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn mul_mod(&mut self, y: &BigImpl, m: &BigImpl) {
        if let (BigImpl::Bn254(v), BigImpl::Bn254(w)) = (y, m) {
            self.value = BIG::mul(&self.value, &v.value).dmod(&w.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
        
    }

    fn add(&mut self, y: &BigImpl) {
        if let BigImpl::Bn254(v) = y {
            self.value.add(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf:Vec<u8> = vec![0;MODBYTES];
        self.value.tobytes(&mut buf);
        buf
    }

    fn to_string(&self) -> String {
        self.value.tostring()
    }

    fn pow_mod(&mut self, y: &BigImpl, m: &BigImpl) {
        if let (BigImpl::Bn254(v), BigImpl::Bn254(w)) = (y, m) {
            self.value = self.value.powmod(&v.value, &w.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn inv_mod(&mut self, m: &BigImpl) {
        if let BigImpl::Bn254(v) = m {
            self.value.invmodp(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }   
    }

    fn sub(&mut self, y: &BigImpl) {
        if let BigImpl::Bn254(v) = y {
            self.value.sub(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }  
    }

    fn imul(&mut self, i: isize) {
        self.value.imul(i);
    }

    fn equals(&self, y: &BigImpl) -> bool {
        if let BigImpl::Bn254(v) = y {
            BIG::comp(&self.value, &v.value) == 0
        } else {
            false
        }  
    }
}

impl Clone for Bn254BIG {
    fn clone(&self) -> Self {
        Self{ value: self.value.clone() }
    }
}