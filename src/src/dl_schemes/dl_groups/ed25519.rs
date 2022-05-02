use derive::Serializable;
use mcore::{ed25519::{big::{BIG, MODBYTES}, ecp::ECP, rom}};
use rasn::{AsnType, Encode, Decode, Encoder, types::BitString, de::Error};
use crate::{dl_schemes::bigint::BigInt, dl_schemes::{DlDomain, dl_groups::dl_group::*}, rand::RNG};

use super::{pairing::PairingEngine};
use crate::dl_schemes::bigint::*;

#[derive(AsnType, Debug, Serializable)]
pub struct Ed25519 {
    value: ECP
}

impl Encode for Ed25519 {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |encoder| {
            self.to_bytes().encode(encoder)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Ed25519 {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        let bytes:Vec<u8> = BitString::decode(decoder)?.into();
        Ok(Self::from_bytes(&bytes))
    }
}

impl PairingEngine for Ed25519 {
    type G2 = Self;

    type G3 = Self;

    fn pair(_g1: &Self::G2, _g2: &Self) -> Self::G3 {
        panic!("Ed22519 does not support pairings!")
    }

    fn ddh(_g1: &Self::G2, _g2: &Self, _g3:&Self::G2, _g4:&Self) -> bool {
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

    fn new_rand(rng: &mut RNG) -> Self {
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

    fn from_bytes(bytes: &[u8]) -> Self {
        Self { value:ECP::frombytes(bytes) }
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

    fn get_name() -> String {
        "ed25519".to_string()
    }
}

impl PartialEq for Ed25519 {
    fn eq(&self, other: &Self) -> bool {
        self.value.equals(&other.value)
    }
}

#[derive(AsnType, Debug, Serializable)]
pub struct Ed25519BIG {
    value: BIG
}

impl Encode for Ed25519BIG {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |encoder| {
            self.to_bytes().encode(encoder)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Ed25519BIG {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        let bytes:Vec<u8> = BitString::decode(decoder)?.into();

        let val = Self::from_bytes(&bytes);

        match val {
            BigImpl::Ed25519(x) => Ok(x),
            _ => panic!("Wrong type after deserializing big integer") // TODO: Change this
        }
    }
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

    fn new_rand(q: &BigImpl, rng: &mut RNG) -> BigImpl {
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

impl PartialEq for Ed25519BIG {
    fn eq(&self, other: &Self) -> bool {
        self.equals(&BigImpl::Ed25519(other.clone()))
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