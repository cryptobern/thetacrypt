use core::slice;
use std::alloc::alloc_zeroed;
use std::mem::{MaybeUninit, self};
use std::ops::{Add, Sub, Mul, Div};
use std::ptr::{null, null_mut};

use derive::Serializable;
use gmp_mpfr_sys::gmp::{mpz_t, self};
use hex::FromHex;
use mcore::rand::RAND;
use rasn::types::BitString;
use rasn::{Encode, AsnType, Encoder, Decode};
use rug::integer::IsPrime;
use rug::ops::{Pow, MulFrom};
use rug::rand::{MutRandState, RandState};
use rug::{Integer, Assign};
use std::ffi::{CStr, c_void};
use std::fmt::Write;

use crate::rand::RNG;

#[macro_export] macro_rules! BIGINT {
    ($x:expr) => {
        RsaBigInt::new_int($x as isize)
    };
}

#[macro_export] macro_rules! ZERO {
    () => {
        RsaBigInt::new_int(0)
    };
}

#[macro_export] macro_rules! ONE {
    () => {
        RsaBigInt::new_int(1)
    };
}

#[derive(Serializable, Debug)]
pub struct RsaBigInt {
    value: Integer
}

impl AsnType for RsaBigInt {
    const TAG: rasn::Tag = rasn::Tag::BIT_STRING;
}

impl Encode for RsaBigInt {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |encoder| {
            self.to_bytes().encode(encoder)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for RsaBigInt {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let mut bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            Ok(Self::from_bytes(&mut bytes))
        })
    }
}

impl PartialEq for RsaBigInt {
    fn eq(&self, other: &Self) -> bool {
        self.equals(&other)
    }
}

impl RsaBigInt {
    pub fn new() -> Self {
        Self {value: Integer::new() }
        
    }

    pub fn new_int(i: isize) -> Self {
        Self { value:Integer::from(i) }
    }

    pub fn new_copy(x: &Self) -> Self {
        Self { value:x.value.clone() }
    }

    pub fn new_rand(rng: &mut RNG, bits: usize) -> Self {
        let mut val = Self::new();
        val.rand(rng, bits);
        val
    }

    pub fn rand(&mut self, rng: &mut RNG, bits: usize) {
        let bytelen = f64::floor(bits as f64/8 as f64) as usize;
        let rem = bits%8;

        let mut s = String::with_capacity(bytelen + rem + 1);
        let mut bytes = Vec::new();

        if rem != 0 {
            let mut mask: u8 = 0;
            let mut byte = rng.getbyte();
            for i in 0..rem {
                mask += 1 << i;

                if i == rem-1 {
                    byte |= 1 << i;
                }
            }   
            
            byte &= mask;
            bytes.push(byte);
            //write!(&mut s, "{:02X}", byte).expect("Unable to get random bytes!");
        }

        for i in 0..bytelen {
            let mut byte = rng.getbyte();
            if i == 0 && rem == 0{
                byte |= 1 << 7;
            }
            bytes.push(byte);
            //write!(&mut s, "{:02X}", byte).expect("Unable to get random bytes!");
        }
        //write!(&mut s, "\0").expect("Unable to null terminate string");

        
        unsafe {
            self.value.assign_bytes_radix_unchecked(&bytes, 256, false);
        }
        
    }

    pub fn new_prime(rng: &mut RNG, len: usize) -> Self {
        let mut x = RsaBigInt::new();

        loop {
            x.rand(rng, len);

            if x.is_prime() {
                break;
            }
        } 
        
        x
    }

    pub fn cmp(&self, y: &Self) -> std::cmp::Ordering {
        self.value.cmp(&y.value)
    }

    pub fn set(&mut self, y: &Self) {
        self.value.assign(&y.value);
    }

    pub fn add(&self, y:&Self) -> Self {
        Self { value:self.value.clone().add(&y.value) }
    }

    pub fn inc(&self, k: u64) -> Self {
        Self { value:self.value.clone().add(k) }
    }

    pub fn sub(&self, y:&Self) -> Self {
        Self { value:self.value.clone().sub(&y.value) }
    }

    pub fn dec(&self, k: u64) -> Self {
        Self { value:self.value.clone().sub(k) }
    }

    pub fn mul(&self, y:&Self) -> Self {
        Self { value:self.value.clone().sub(&y.value) }
    }

    pub fn rmod(&self, m:&Self) -> Self {
        Self { value:self.value.clone().pow_mod(&Integer::from(1), &m.value).unwrap() }
    }

    pub fn mul_mod(&self, y:&Self, m:&Self) -> Self {
        Self { value:y.value.clone().mul(&y.value).pow_mod(&Integer::from(1), &m.value).unwrap() }
    }

    pub fn pow(&self, y: u32) -> Self {
        Self { value:self.value.clone().pow(y) }
    }

    pub fn pow_mod(&self, e:&Self, m:&Self) -> Self {
        Self { value:self.value.clone().pow_mod(&e.value, &m.value).unwrap() }
    }

    pub fn root(&mut self, n: u32) -> Self {
        Self { value:self.value.clone().root(n) }
    }

    pub fn inv_mod(&self, m:&Self) -> Self {
        Self { value:self.value.clone().invert(&m.value).unwrap() }
    }

    pub fn equals(&self, y:&Self) -> bool {
        self.cmp(&y).is_eq()
    }

    pub fn imul(&self, i: isize) -> Self {
        let mut val = self.clone();
        val.value.mul_from(i);
        val
    }

    pub fn is_prime(&self) -> bool {
        self.value.is_probably_prime(45).eq(&IsPrime::Yes)
    }

    pub fn is_even(&self) -> bool {
        self.value.is_even()
    }

    pub fn jacobi(x: &Self, y:&Self) -> i32 {
        x.value.jacobi(&y.value)
    }

    pub fn coprime(&self, u:u32) -> bool {
        self.value.is_divisible_u(u)
    }

    pub fn div(&self, y: &Self) -> Self {
        Self { value:self.value.clone().div(&y.value) }
    }

    pub fn legendre(&self, y: &Self) -> i32 {
        self.value.legendre(&y.value)
    }

    pub fn to_string(&self) -> String {
        self.value.to_string()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let size:usize = 0;
        let size_ptr = &size as *const usize;

        unsafe {
            let bytes_ptr = gmp::mpz_export(null_mut(), size_ptr as *mut usize, 1, 1, 1, 0, self.value.as_raw()) as *mut u8;
            let bytes:Vec<u8> = slice::from_raw_parts(bytes_ptr, size).to_vec();
            bytes
        }
    }

    pub fn from_bytes(bytes: &mut [u8]) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            let op: *const c_void = bytes.as_ptr() as *const c_void;
            gmp::mpz_init(z.as_mut_ptr()); 
            gmp::mpz_import(z.as_mut_ptr(), bytes.len(), 1, 1, 1, 0, op);
            Self { value: Integer::from_raw(z.assume_init()) }
        }
    }
}

impl Clone for RsaBigInt {
    fn clone(&self) -> Self {
        RsaBigInt::new_copy(&self)
    }
}