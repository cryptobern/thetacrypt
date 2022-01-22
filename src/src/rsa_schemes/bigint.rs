use std::mem::MaybeUninit;

use gmp_mpfr_sys::gmp::{mpz_t, self};
use hex::FromHex;
use mcore::rand::RAND;
use std::ffi::CStr;
use std::fmt::Write;

#[macro_export] macro_rules! BIGINT {
    ($x:expr) => {
        BigInt::new_int($x as isize)
    };
}

#[macro_export] macro_rules! ZERO {
    () => {
        BigInt::new_int(0)
    };
}

#[macro_export] macro_rules! ONE {
    () => {
        BigInt::new_int(1)
    };
}

pub struct BigInt {
    value: MaybeUninit<mpz_t>
}

impl BigInt {

    pub fn new() -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr());
            Self {value: z }
        }
    }

    pub fn new_int(i: isize) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr());
            gmp::mpz_set_si(z.as_mut_ptr(), i as i64);
            Self {value: z }
        }
    }

    pub fn new_copy(x: &Self) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init_set(z.as_mut_ptr(), x.value.as_ptr());
            Self { value: z }
        }
    }

    pub fn new_rand(rng: &mut impl RAND, len: usize) -> Self {
        unsafe {
            let mut s = String::with_capacity(2*len + 1);
            for _ in 0..len {
                write!(&mut s, "{:02X}", rng.getbyte()).expect("Unable to get random bytes!");
            }

            let mut z = MaybeUninit::uninit();
            gmp::mpz_init_set_str(z.as_mut_ptr(), s.as_ptr() as *const i8, 16);
            Self { value: z }
        }
    }

    pub fn rand(&mut self, rng: &mut impl RAND, len: usize) {
        unsafe {
            let mut s = String::with_capacity(2*len + 1);
            for _ in 0..len {
                write!(&mut s, "{:02X}", rng.getbyte()).expect("Unable to get random bytes!");
            }

            gmp::mpz_set_str(self.value.as_mut_ptr(), s.as_ptr() as *const i8, 16);
        }
    }

    pub fn new_prime(rng: &mut impl RAND, len: usize) -> Self {
        let mut x = BigInt::new();

        loop {
            x.rand(rng, len);

            if x.is_prime() {
                break;
            }
        } 
        
        x
    }

    pub fn set(&mut self, y: &Self) {
        unsafe {
            gmp::mpz_set(self.value.as_mut_ptr(), y.value.as_ptr());
        }
    }

    pub fn _add(x: &Self, y:&Self) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr());
            gmp::mpz_add(z.as_mut_ptr(), x.value.as_ptr(), y.value.as_ptr());
            Self { value: z }
        }
    }

    pub fn add(&mut self, y:&Self) {
        unsafe {
            gmp::mpz_add(self.value.as_mut_ptr(), self.value.as_ptr(), y.value.as_ptr());
        }
    }

    pub fn inc(&mut self, k: u64) {
        unsafe {
            gmp::mpz_add_ui(self.value.as_mut_ptr(), self.value.as_ptr(), k);
        }
    }

    pub fn _sub(x: &Self, y:&Self) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr());
            gmp::mpz_sub(z.as_mut_ptr(), x.value.as_ptr(), y.value.as_ptr());
            Self { value: z }
        }
    }

    pub fn sub(&mut self, y:&Self) {
        unsafe {
            gmp::mpz_sub(self.value.as_mut_ptr(), self.value.as_ptr(), y.value.as_ptr());
        }
    }

    pub fn dec(&mut self, k: u64) {
        unsafe {
            gmp::mpz_sub_ui(self.value.as_mut_ptr(), self.value.as_ptr(), k);
        }
    }

    pub fn _mul(x: &Self, y:&Self) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr());
            gmp::mpz_mul(z.as_mut_ptr(), x.value.as_ptr(), y.value.as_ptr());
            Self { value: z }
        }
    }

    pub fn mul(&mut self, y:&Self) {
        unsafe {
            gmp::mpz_mul(self.value.as_mut_ptr(), self.value.as_ptr(), y.value.as_ptr());
        }
    }

    pub fn _rmod(x: &Self, m:&Self) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr());
            gmp::mpz_mod(z.as_mut_ptr(), x.value.as_ptr(), m.value.as_ptr());
            Self { value: z }
        }
    }

    pub fn rmod(&mut self, m: &Self) {
        unsafe {
            gmp::mpz_mod(self.value.as_mut_ptr(), self.value.as_ptr(), m.value.as_ptr());
        }
    }

    pub fn _mul_mod(x: &Self, y:&Self, m:&Self) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr());
            gmp::mpz_mul(z.as_mut_ptr(), x.value.as_ptr(), y.value.as_ptr()); 
            gmp::mpz_mod(z.as_mut_ptr(), z.as_ptr(), m.value.as_ptr());
            Self { value: z }
        }
    }

    pub fn mul_mod(&mut self, y:&Self, m: &Self) {
        unsafe {
            gmp::mpz_mul(self.value.as_mut_ptr(), self.value.as_ptr(), y.value.as_ptr()); 
            gmp::mpz_mod(self.value.as_mut_ptr(), self.value.as_ptr(), m.value.as_ptr());
        }
    }

    pub fn pow(&mut self, y: u64) {
        unsafe {
            gmp::mpz_pow_ui(self.value.as_mut_ptr(), self.value.as_ptr(), y as u64);
        }
    }

    pub fn _pow(x: &Self, y: u64) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr());
            gmp::mpz_pow_ui(z.as_mut_ptr(), x.value.as_ptr(), y as u64);
            Self { value: z }
        }
    }

    pub fn _pow_mod(x: &Self, e:&Self, m:&Self) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr());
            gmp::mpz_powm(z.as_mut_ptr(), x.value.as_ptr(), e.value.as_ptr(), m.value.as_ptr());
            Self { value: z }
        }
    }

    pub fn pow_mod(&mut self, e:&Self, m: &Self) {
        unsafe {
            gmp::mpz_powm(self.value.as_mut_ptr(), self.value.as_ptr(), e.value.as_ptr(), m.value.as_ptr());
        }
    }

    pub fn root(&mut self, n: u64) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr()); 
            gmp::mpz_rootrem(self.value.as_mut_ptr(), z.as_mut_ptr(), self.value.as_ptr(), n as u64);
            Self { value: z }
        }
    }

    pub fn _inv_mod(x: &Self, m:&Self) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr());
            gmp::mpz_invert(z.as_mut_ptr(), x.value.as_ptr(), m.value.as_ptr());
            Self { value: z }
        }
    }

    pub fn inv_mod(&mut self, m:&Self) {
        unsafe {
            gmp::mpz_invert(self.value.as_mut_ptr(), self.value.as_ptr(), m.value.as_ptr());
        }
    }

    pub fn equals(&self, y:&Self) -> bool {
        unsafe {
            gmp::mpz_cmp(self.value.as_ptr(), y.value.as_ptr()) == 0
        }
    }

    pub fn imul(&mut self, i: isize) {
        unsafe {
            gmp::mpz_mul_si(self.value.as_mut_ptr(), self.value.as_ptr(), i as i64);
        }
    }

    pub fn _imul(x: &Self, i: isize) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr());  
            gmp::mpz_mul_si(z.as_mut_ptr(), x.value.as_ptr(), i as i64);
            
            Self { value:z }
        }
    }

    pub fn is_prime(&self) -> bool {
        unsafe {
            gmp::mpz_probab_prime_p(self.value.as_ptr(), 45) != 0
        }
    }

    pub fn is_even(&self) -> bool {
        unsafe {
            gmp::mpz_even_p(self.value.as_ptr()) != 0
        }
    }

    pub fn lshift(&mut self, k: u64) {
        unsafe {
            gmp::mpz_mul_2exp(self.value.as_mut_ptr(), self.value.as_ptr(), k);
        }
    }

    pub fn rshift(&mut self, k: u64) {
        unsafe {
            gmp::mpz_tdiv_q_2exp(self.value.as_mut_ptr(), self.value.as_ptr(), k);
        }
    }

    pub fn jacobi(x: &Self, y:&Self) -> isize {
        unsafe {
            gmp::mpz_jacobi(x.value.as_ptr(), y.value.as_ptr()) as isize
        }
    }

    pub fn coprime(&self, i:isize) -> bool {
        unsafe {
            let x = BigInt::new_int(i);
            let mut y = BigInt::new();
            gmp::mpz_gcd(y.value.as_mut_ptr(), self.value.as_ptr(), x.value.as_ptr());
            y.equals(&BigInt::new_int(1))
        }
    }

    pub fn _div(x: &Self, y: &Self) -> Self {
        unsafe {
            let mut z = MaybeUninit::uninit();
            gmp::mpz_init(z.as_mut_ptr());          
            gmp::mpz_fdiv_q(z.as_mut_ptr(), x.value.as_ptr(), y.value.as_ptr());
            Self { value: z }
        }
    }

    pub fn div(&mut self, y: &Self) {
        unsafe {        
            gmp::mpz_fdiv_q(self.value.as_mut_ptr(), self.value.as_ptr(), y.value.as_ptr());
        }
    }

    pub fn legendre(&self, y: &Self) -> isize {
        unsafe {
            gmp::mpz_legendre(self.value.as_ptr(), y.value.as_ptr()) as isize
        }
    }

    pub fn to_string(&self) -> String {
        unsafe {
            let str = gmp::mpz_get_str(std::ptr::null_mut(), 16, self.value.as_ptr());
            let s:String = CStr::from_ptr(str).to_str().unwrap().to_string();
            s
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut s = self.to_string();
        if s.len() % 2 == 1 {
            s.insert(0, '0');
        }
        Vec::from_hex(s).expect("Invalid hex string")
    }

    pub fn from_bytes(bytes: &mut [u8]) -> Self {
        unsafe {
            let mut s = String::with_capacity(2*bytes.len() + 1);
            for i in 0..bytes.len() {
                write!(&mut s, "{:02X}", bytes[i]).expect("Unable to read from bytes!");
            }

            let mut z = MaybeUninit::uninit();
            gmp::mpz_init_set_str(z.as_mut_ptr(), s.as_ptr() as *const i8, 16);
            Self { value: z }
        }
    }
}

impl Clone for BigInt {
    fn clone(&self) -> Self {
        BigInt::new_copy(&self)
    }
}