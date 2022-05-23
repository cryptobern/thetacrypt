use derive::Serializable;
use mcore::{bls12381::{big::{BIG, MODBYTES}, ecp::{ECP}, ecp2::ECP2, fp12::FP12, pair, rom}};
use rasn::{AsnType, Decode, Decoder, Encode, Encoder, Tag, types::{OctetString, BitString}};
use crate::{dl_schemes::bigint::BigInt, dl_schemes::{DlDomain, dl_groups::dl_group::*}, rand::RNG};
use crate::dl_schemes::dl_groups::pairing::*;
use crate::dl_schemes::bigint::*;

#[derive(Debug, Serializable)]
pub struct Bls12381 {
    value: ECP
}


impl PartialEq for Bls12381 {
    fn eq(&self, other: &Self) -> bool {
        self.value.equals(&other.value)
    }
}

impl PairingEngine for Bls12381 {
    type G2 = Bls12381ECP2;
    type G3 = Bls12381FP12;

    fn pair(g1: &Self::G2, g2: &Self) -> Self::G3 {
        let mut rhs = pair::ate(&g1.value, &g2.value);
        rhs = pair::fexp(&rhs);
        Self::G3 { value: rhs} 
    }

    fn ddh(g1: &Self::G2, g2: &Self, g3:&Self::G2, g4:&Self) -> bool {
        Self::pair(g1, g2).equals(&Self::pair(g3, g4))
    }
}

impl DlDomain for Bls12381 {
    fn is_pairing_friendly() -> bool {
        true
    }
}

impl DlGroup for Bls12381 {
    type BigInt = Bls12381BIG;
    type DataType = ECP;

    fn new() -> Self {
        Self { value:ECP::generator() }
    }
    
    fn new_pow_big (x: &BigImpl) -> Self {
        if let BigImpl::Bls12381(v) = x {
            Self { value:ECP::generator().mul(&v.value)}
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn new_rand(rng: &mut RNG) -> Self {
        Self::new_pow_big(&BigImpl::Bls12381(Self::BigInt { value:BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng) }))
    }

    fn new_copy(g: &Self) -> Self {
        Self { value:g.value.clone() }
    }

    fn mul(&mut self, g: &Self) {
        self.value.add(&g.value);
    }

    fn pow (&mut self, x: &BigImpl) {
        if let BigImpl::Bls12381(v) = x {
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
        let mut buf:Vec<u8> = vec![0;2 * MODBYTES + 1];
        self.value.tobytes(&mut buf, false);
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
        BigImpl::Bls12381(x.clone())    
    }

    fn nbytes() -> usize {
        2*MODBYTES 
    }

    fn to_string(&self) -> String {
        self.value.tostring()
    }

    fn get_name() -> String {
        "bls12381".to_string()
    }
}

#[derive(Debug, Serializable)]
pub struct Bls12381ECP2 {
    value: ECP2
}

impl PartialEq for Bls12381ECP2 {
    fn eq(&self, other: &Self) -> bool {
        self.value.equals(&other.value)
    }
}

impl DlGroup for Bls12381ECP2 {
    type BigInt = Bls12381BIG;
    type DataType = ECP2;

    fn new() -> Self {
        Self { value:ECP2::generator() }
    }
    
    fn new_pow_big (x: &BigImpl) -> Self {
        if let BigImpl::Bls12381(v) = x {
            Self { value:ECP2::generator().mul(&v.value)}
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn new_rand(rng: &mut RNG) -> Self {
        Self::new_pow_big(&BigImpl::Bls12381(Self::BigInt { value:BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng) }))
    }

    fn new_copy(g: &Self) -> Self {
        Self { value:g.value.clone() }
    }

    fn mul(&mut self, g: &Self) {
        self.value.add(&g.value);
    }

    fn pow (&mut self, x: &BigImpl) {
        if let BigImpl::Bls12381(v) = x {
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
        let mut buf:Vec<u8> = vec![0;4*MODBYTES + 1];
        self.value.tobytes(&mut buf, false);
        buf
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        Self { value:ECP2::frombytes(bytes) }
    }

    fn equals(&self, g: &Self) -> bool {
        self.value.equals(&g.value)
    }

    fn get_order() -> BigImpl {
        Self::BigInt::new_ints(&rom::CURVE_ORDER)
    }

    fn wrp(x: &Self::BigInt) -> BigImpl {
        BigImpl::Bls12381(x.clone())    
    }

    fn nbytes() -> usize {
        2*MODBYTES 
    }

    fn to_string(&self) -> String {
        self.value.tostring()
    }

    fn get_name() -> String {
        "bls12381".to_string()
    }
}

#[derive(Serializable)]
pub struct Bls12381FP12 {
    value: FP12
}

impl rasn::AsnType for Bls12381FP12 {
    const TAG: rasn::Tag = rasn::Tag::OCTET_STRING;
}

impl Encode for Bls12381FP12 {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        self.to_bytes().encode(encoder)?;
        Ok(())
    }
}

impl Decode for Bls12381FP12 {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        let bytes:Vec<u8> = Vec::<u8>::decode(decoder)?.into();
        Ok(Self::from_bytes(&bytes))
    }
}

impl PartialEq for Bls12381FP12 {
    fn eq(&self, other: &Self) -> bool {
        self.value.equals(&other.value)
    }
}

impl DlGroup for Bls12381FP12 {
    type BigInt = Bls12381BIG;
    type DataType = FP12;

    fn new() -> Self {
        Self { value:FP12::new() }
    }
    
    fn new_pow_big (x: &BigImpl) -> Self {
        if let BigImpl::Bls12381(v) = x {
            Self { value:FP12::new().pow(&v.value)}
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn new_rand(rng: &mut RNG) -> Self {
        Self::new_pow_big(&BigImpl::Bls12381(Self::BigInt { value:BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng) }))
    }

    fn new_copy(g: &Self) -> Self {
        Self { value:g.value.clone() }
    }

    fn mul(&mut self, g: &Self) {
        self.value.mul(&g.value);
    }

    fn pow (&mut self, x: &BigImpl) {
        if let BigImpl::Bls12381(v) = x {
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

    fn from_bytes(bytes: &[u8]) -> Self {
        Self { value:FP12::frombytes(bytes) }
    }

    fn equals(&self, g: &Self) -> bool {
        self.value.equals(&g.value)
    }

    fn get_order() -> BigImpl {
        Self::BigInt::new_ints(&rom::CURVE_ORDER)
    }

    fn wrp(x: &Self::BigInt) -> BigImpl {
        BigImpl::Bls12381(x.clone())    
    }

    fn nbytes() -> usize {
        MODBYTES
    }

    fn to_string(&self) -> String {
        self.value.tostring()
    }

    fn get_name() -> String {
        "bls12381".to_string()
    }
}

impl Clone for Bls12381FP12 {
    fn clone(&self) -> Self {
        Self{ value: self.value.clone() }
    }
}

impl Clone for Bls12381 {
    fn clone(&self) -> Self {
        Self{ value: self.value.clone() }
    }
}

impl Clone for Bls12381ECP2 {
    fn clone(&self) -> Self {
        Self{ value: self.value.clone() }
    }
}

#[derive(Debug, AsnType, Serializable)]
pub struct Bls12381BIG {
    value: BIG
}

impl Encode for Bls12381BIG {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        self.to_bytes().encode(encoder)?;
        Ok(())
    }
}

impl Decode for Bls12381BIG {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        let bytes:Vec<u8> = Vec::<u8>::decode(decoder)?.into();

        let val = Self::from_bytes(&bytes);

        match val {
            BigImpl::Bls12381(x) => Ok(x),
            _ => panic!("Wrong type after deserializing big integer") // TODO: Change this
        }
    }
}

impl PartialEq for Bls12381BIG {
    fn eq(&self, other: &Self) -> bool {
        self.equals(&BigImpl::Bls12381(other.clone()))
    }
}

impl BigInt for Bls12381BIG {
    type DataType = BIG;

    fn new() -> BigImpl {
        BigImpl::Bls12381(Self { value: BIG::new() })
    }

    fn new_big(y: &BigImpl) -> BigImpl {
        if let BigImpl::Bls12381(v) = y {
            BigImpl::Bls12381(Self { value: BIG::new_big(&v.value)})
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn new_copy(y: &BigImpl) -> BigImpl {
        if let BigImpl::Bls12381(v) = y {
            BigImpl::Bls12381(Self { value:BIG::new_copy(&v.value) })
        } else {
            panic!("Incompatible big integer implementation!");
        }
        
    }

    fn new_ints(a: &[mcore::arch::Chunk]) -> BigImpl {
        BigImpl::Bls12381(Self { value:BIG::new_ints(a) })
    }

    fn new_int(i: isize) -> BigImpl {
        BigImpl::Bls12381(Self { value:BIG::new_int(i) })
    }

    fn new_rand(q: &BigImpl, rng: &mut RNG) -> BigImpl {
        if let BigImpl::Bls12381(v) = q {
            BigImpl::Bls12381(Self { value:BIG::randomnum(&v.value, rng) })
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn from_bytes(bytes: &[u8]) -> BigImpl {
        BigImpl::Bls12381(Self { value:BIG::frombytes(bytes)})
    }

    fn rmod(&mut self, y: &BigImpl) {
        if let BigImpl::Bls12381(v) = y {
            self.value.rmod(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn mul_mod(&mut self, y: &BigImpl, m: &BigImpl) {
        if let (BigImpl::Bls12381(v), BigImpl::Bls12381(w)) = (y, m) {
            self.value = BIG::mul(&self.value, &v.value).dmod(&w.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
        
    }

    fn add(&mut self, y: &BigImpl) {
        if let BigImpl::Bls12381(v) = y {
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
        if let (BigImpl::Bls12381(v), BigImpl::Bls12381(w)) = (y, m) {
            self.value = self.value.powmod(&v.value, &w.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn inv_mod(&mut self, m: &BigImpl) {
        if let BigImpl::Bls12381(v) = m {
            self.value.invmodp(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }   
    }

    fn sub(&mut self, y: &BigImpl) {
        if let BigImpl::Bls12381(v) = y {
            self.value.sub(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }  
    }

    fn imul(&mut self, i: isize) {
        self.value.imul(i);
    }

    fn equals(&self, y: &BigImpl) -> bool {
        if let BigImpl::Bls12381(v) = y {
            BIG::comp(&self.value, &v.value) == 0
        } else {
            false
        }  
    }
}

impl Clone for Bls12381BIG {
    fn clone(&self) -> Self {
        Self{ value: self.value.clone() }
    }
}

impl rasn::AsnType for Bls12381 {
    const TAG: rasn::Tag = rasn::Tag::OCTET_STRING;
}

impl Decode for Bls12381 {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, tag: Tag) -> Result<Self, D::Error> {
        // Accepts a closure that decodes the contents of the sequence.
        decoder.decode_sequence(tag, |decoder| {
            let bytes = OctetString::decode(decoder)?;
            let value = ECP::frombytes(&bytes);
            Ok(Self { value })
        })
    }
}

impl Encode for Bls12381 {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        // Accepts a closure that encodes the contents of the sequence.
        encoder.encode_sequence(tag, |encoder| {
            let bytes = self.to_bytes();

            let octets = OctetString::from(bytes);
            octets.encode(encoder)?;

            Ok(())
        })?;

        Ok(())
    }
}

impl AsnType for Bls12381ECP2 {
    const TAG: Tag = Tag::OCTET_STRING;
}

impl Decode for Bls12381ECP2 {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, tag: Tag) -> Result<Self, D::Error> {
        // Accepts a closure that decodes the contents of the sequence.
        decoder.decode_sequence(tag, |decoder| {
            let bytes = OctetString::decode(decoder)?;

            Ok(Self::from_bytes(&bytes))
        })
    }
}

impl Encode for Bls12381ECP2 {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        // Accepts a closure that encodes the contents of the sequence.
        encoder.encode_sequence(tag, |encoder| {
            let bytes = self.to_bytes();

            let octets = OctetString::from(bytes);
            octets.encode(encoder)?;

            Ok(())
        })?;

        Ok(())
    }
}