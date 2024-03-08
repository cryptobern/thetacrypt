use core::slice;
use std::mem::MaybeUninit;
use std::ops::{Add, Div, Mul, Sub};
use std::ptr::null_mut;

use gmp_mpfr_sys::gmp::{self};
use mcore::rand::RAND;
use rug::integer::IsPrime;
use rug::ops::{MulFrom, Pow};
use rug::{Assign, Integer};
use std::ffi::c_void;

use crate::rand::RNG;

#[macro_export]
macro_rules! BIGINT {
    ($x:expr) => {
        BigInt::new_int($x as isize)
    };
}

#[macro_export]
macro_rules! ZERO {
    () => {
        BigInt::new_int(0)
    };
}

#[macro_export]
macro_rules! ONE {
    () => {
        BigInt::new_int(1)
    };
}

#[derive(Debug)]
pub struct BigInt {
    value: Integer,
}

impl PartialEq for BigInt {
    fn eq(&self, other: &Self) -> bool {
        self.equals(&other)
    }
}

impl BigInt {
    /* create new integer (initialized to 0) */
    pub fn new() -> Self {
        Self {
            value: Integer::new(),
        }
    }

    /* create new integer and initialize with i */
    pub fn new_int(i: isize) -> Self {
        Self {
            value: Integer::from(i),
        }
    }

    /* returns a copy of x */
    pub fn new_copy(x: &Self) -> Self {
        Self {
            value: x.value.clone(),
        }
    }

    /* returns a random integer of bit size bits */
    pub fn new_rand(rng: &mut RNG, bits: usize) -> Self {
        let mut val = Self::new();
        val.rand(rng, bits);
        val
    }

    /* assigns a random value of bit size bits to self */
    pub fn rand(&mut self, rng: &mut RNG, bits: usize) {
        let bytelen = f64::floor(bits as f64 / 8 as f64) as usize;
        let rem = bits % 8;
        let mut bytes = Vec::new();

        if rem != 0 {
            let mut mask: u8 = 0;
            let mut byte = rng.getbyte();
            for i in 0..rem {
                mask += 1 << i;

                if i == rem - 1 {
                    byte |= 1 << i;
                }
            }

            byte &= mask;
            bytes.push(byte);
        }

        for i in 0..bytelen {
            let mut byte = rng.getbyte();
            if i == 0 && rem == 0 {
                byte |= 1 << 7;
            }
            bytes.push(byte);
        }

        unsafe {
            self.value.assign_bytes_radix_unchecked(&bytes, 256, false);
        }
    }

    /* generates a new random prime of bit length len */
    pub fn new_prime(rng: &mut RNG, len: usize) -> Self {
        let mut x = BigInt::new();

        loop {
            x.rand(rng, len);

            if x.is_prime() {
                break;
            }
        }

        x
    }

    /* compares y to self */
    pub fn cmp(&self, y: &Self) -> std::cmp::Ordering {
        self.value.cmp(&y.value)
    }

    /* set self to y */
    pub fn set(&mut self, y: &Self) {
        self.value.assign(&y.value);
    }

    /* returns self + y */
    pub fn add(&self, y: &Self) -> Self {
        Self {
            value: self.value.clone().add(&y.value),
        }
    }

    /* returns self + k */
    pub fn inc(&self, k: u64) -> Self {
        Self {
            value: self.value.clone().add(k),
        }
    }

    /* returns self - y */
    pub fn sub(&self, y: &Self) -> Self {
        Self {
            value: self.value.clone().sub(&y.value),
        }
    }

    /* returns self - k */
    pub fn dec(&self, k: u64) -> Self {
        Self {
            value: self.value.clone().sub(k),
        }
    }

    /* returns self*y  */
    pub fn mul(&self, y: &Self) -> Self {
        Self {
            value: self.value.clone().mul(&y.value),
        }
    }

    /* returns self % m */
    pub fn rmod(&self, m: &Self) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr());
            gmp::mpz_mod(z.as_mut_ptr(), self.value.as_raw(), m.value.as_raw());
            Self {
                value: Integer::from_raw(z.assume_init()),
            }
        }
    }

    /* returns (self * y) % m */
    pub fn mul_mod(&self, y: &Self, m: &Self) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr());
            gmp::mpz_mul(z.as_mut_ptr(), self.value.as_raw(), y.value.as_raw());
            gmp::mpz_mod(z.as_mut_ptr(), z.as_ptr(), m.value.as_raw());
            Self {
                value: Integer::from_raw(z.assume_init()),
            }
        }
    }

    /* returns self^y */
    pub fn pow(&self, y: u32) -> Self {
        Self {
            value: self.value.clone().pow(y),
        }
    }

    /* returns self^e % m */
    pub fn pow_mod(&self, e: &Self, m: &Self) -> Self {
        Self {
            value: self.value.clone().pow_mod(&e.value, &m.value).unwrap(),
        }
    }

    /* returns the n-th root of self */
    pub fn root(&mut self, n: u32) -> Self {
        Self {
            value: self.value.clone().root(n),
        }
    }

    /* returns self^(-1) % m */
    pub fn inv_mod(&self, m: &Self) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr());
            gmp::mpz_invert(z.as_mut_ptr(), self.value.as_raw(), m.value.as_raw());
            Self {
                value: Integer::from_raw(z.assume_init()),
            }
        }
    }

    /* returns true if self == y, false otherwise */
    pub fn equals(&self, y: &Self) -> bool {
        self.cmp(&y).is_eq()
    }

    /* returns self*i */
    pub fn imul(&self, i: isize) -> Self {
        let mut val = self.clone();
        val.value.mul_from(i);
        val
    }

    /* returns true if self is prime, false otherwise */
    pub fn is_prime(&self) -> bool {
        !self.value.is_probably_prime(45).eq(&IsPrime::No)
    }

    /* returns true if self is even, false otherwise */
    pub fn is_even(&self) -> bool {
        self.value.is_even()
    }

    /* returns the jacobi symbol (x/y) */
    pub fn jacobi(x: &Self, y: &Self) -> isize {
        x.value.jacobi(&y.value) as isize
    }

    /* returns true if self is coprime to i, false otherwise */
    pub fn coprime(&self, i: isize) -> bool {
        !self.value.is_divisible(&Integer::from(i))
    }

    /* returns self/y */
    pub fn div(&self, y: &Self) -> Self {
        Self {
            value: self.value.clone().div(&y.value),
        }
    }

    /* returns the legendre symbol  */
    pub fn legendre(&self, y: &Self) -> isize {
        unsafe { gmp::mpz_legendre(self.value.as_raw(), y.value.as_raw()) as isize }
    }

    /* convert value to string */
    pub fn to_string(&self) -> String {
        self.value.to_string()
    }

    /* serializes value to bytes and returns byte vector */
    pub fn to_bytes(&self) -> Vec<u8> {
        let size: usize = 0;
        let size_ptr = &size as *const usize;

        unsafe {
            let bytes_ptr = gmp::mpz_export(
                null_mut(),
                size_ptr as *mut usize,
                1,
                1,
                1,
                0,
                self.value.as_raw(),
            ) as *mut u8;
            let bytes: Vec<u8> = slice::from_raw_parts(bytes_ptr, size).to_vec();
            bytes
        }
    }

    /* serializes value to bytes and pads with zeroes until byte vector fits specified length */
    pub fn to_sized_bytes(&self, len: usize) -> Result<Vec<u8>, String> {
        let mut bytes = self.to_bytes();

        if bytes.len() > len {
            return Err("Value is too big to fit into required size".to_string());
        }

        /* pad with zeroes at the beginning (big endian) encoding */
        while bytes.len() < len {
            bytes.insert(0, 0);
        }

        Ok(bytes)
    }

    /* deserializes from byte vector */
    pub fn from_bytes(bytes: &[u8]) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            let op: *const c_void = bytes.as_ptr() as *const c_void;
            gmp::mpz_init(z.as_mut_ptr());
            gmp::mpz_import(z.as_mut_ptr(), bytes.len(), 1, 1, 1, 0, op);
            Self {
                value: Integer::from_raw(z.assume_init()),
            }
        }
    }
}

impl Clone for BigInt {
    fn clone(&self) -> Self {
        BigInt::new_copy(&self)
    }
}
