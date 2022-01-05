use mcore::{rand::RAND, rsa2048::{big::{BIG, MODBYTES}, ff::{DF, SF, SL}}};

use crate::{bigint::{BigImpl, BigInt}, rsa_schemes::common::extend};

use super::{rsa_domain::{BigFiniteField, RsaDomain}};

pub struct Rsa2048 {
    value: SF,
}

impl RsaDomain for Rsa2048 {
    type BigInt = Rsa2048BIG;
    type DF = Rsa2048DF;

    type DataType = SF;

    fn new() -> Self {
        Self{ value: SF::new() }
    }

    fn new_pow(x: &Self, m: &Self) -> Self {
        let mut v = SF::new();
        v.skpow(&x.value, &m.value);

        Self{ value: v}
    }

    fn new_rand(rng: &mut impl RAND, len: usize) -> Self {
        let mut g = Self::new();
        g.rand(rng, len);
        g
    }

    fn new_prime(rng: &mut impl RAND, len:usize) -> Self {
        let mut e_bytes = Vec::new();
        if len%8 != 0 {
            panic!("invalid bit size!");
        }

        for _ in 0..len/8 {
            e_bytes.push(rng.getbyte());
        }

        Self::from_bytes(&mut e_bytes)
    }

    fn new_copy(y: &Self) -> Self {
        let mut v = SF::new();
        v.copy(&y.value);

        Self{ value: v}
    }

    fn mul(&self, y: &Self) -> Self::DF {
        Self::DF { value:self.value.mul(&y.value) }
    }

    fn add(&mut self, y: &Self) {
        self.value.add(&y.value);
    }

    fn pow(&mut self, x: &Self, m: &Self) {
        self.value.skpow(&x.value, &m.value);
    }

    fn invmodp(&mut self, p: &Self) {
        self.value.invmodp(&p.value);
    }

    fn set(&mut self, y: &Self::DataType) {
        self.value.copy(y);
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut c = self.clone();
        let mut v:Vec<u8> = vec![0;MODBYTES];
        c.value.tobytes(&mut v);

        v
    }

    fn from_bytes(bytes: &mut [u8]) -> Self {
        let mut extbytes = bytes.to_vec();
        if bytes.len() < MODBYTES {
            extbytes = extend(bytes, MODBYTES);
        } else if bytes.len() > MODBYTES {
            println!("Invalid length: {}", bytes.len());
            panic!("Invalid length of field encoding");
        }
        
        let mut v = SF::new();
        v.frombytes(&extbytes);

        let t = Self { value: v };
        t
    }

    fn equals(&self, y: &Self) -> bool {
        self.value.comp(&y.value) == 0
    }

    fn to_string(&self) -> String {
        self.value.tostring()
    }

    fn rand(&mut self, rng: &mut impl RAND, len:usize) {
        self.value.random(rng);

        let mut l = len;

        if l > MODBYTES*8 {
            l = MODBYTES*8;
        }

        let diff:f32 = (l as f32)/8f32;
        let lbytes = diff.floor() as usize;

        let mut t = Vec::new();
        
        for _ in 0..(MODBYTES - lbytes) {
            t.push(0);
        }

        for _ in 0..lbytes as usize {
            t.push(rng.getbyte());
        }

        self.value = Self::from_bytes(&mut t).value;
    }

    fn sub(&mut self, y: &Self) {
        self.value.sub(&y.value);
    }

    fn new_int(i: isize) -> Self {
        let mut t = SF::new();
        t.set(i);
        Self{ value: t }
    }
    /* 
    fn is_prime(&self, rng: &mut impl RAND) -> bool {
        self.value.isprime(rng)
    }*/

    fn last_bits(&mut self, n: usize) -> isize {
        self.value.lastbits(n)
    }

    fn inc(&mut self, i: isize) {
        self.value.inc(i);
    }

    fn dec(&mut self, i: isize) {
        self.value.dec(i);
    }

    fn copy(&mut self, y: &Self) {
        self.value.copy(&y.value);
    }

    fn dmod(x: &mut Self::DF, p: &Self) -> Self {
        Self { value: x.value.dmod(&p.value) }
    }

    fn mul_mod(&mut self, y: &Self, p: &Self) {
        self.value = self.value.mul(&y.value).dmod(&p.value);
    }

    fn cfactor(&self, x: isize) -> bool {
        self.value.cfactor(x)
    }

    fn shr(&mut self) {
        self.value.shr();
    }
    fn shl(&mut self) {
        self.value.shl();
    }

    fn parity(&self) -> isize {
        self.value.parity()
    }

    fn norm(&mut self) {
        self.value.norm();
    }

    fn rmod(&mut self, p: &Self) {
        self.value.rmod(&p.value);
    }

    fn jacobi(&self, x: &Self::DF) -> i8 {
        assert!(x.parity() == 1);
        let mut n = Self::to_df(&self.clone());
        let mut k = x.clone();

        n.rmod(x);

        let mut t = 1;
        let l = Self::new_int(4);

        while !n.equals_int(0) {
            while n.parity() == 0 {
                n.shr();

                let mut r = k.clone();
                Self::dmod(&mut r, &Self::new_int(8));
                if r.equals_int(3) || r.equals_int(5) {
                    t = -t;
                }
            }
            
            let tmp = n.clone();
            n = k;
            k = tmp;
            
            if Self::dmod(&mut n, &l).equals_int(3) && Self::dmod(&mut k, &l).equals_int(3) {
                t = -t;
            }

            n.rmod(&k);
        }
        if k.equals_int(1) {
            t
        } else {
            0
        }
    }

    fn is_prime(&self, rng: &mut impl RAND) -> bool {
        self.value.isprime(rng)
    }
}

impl Clone for Rsa2048 {
    fn clone(&self) -> Self {
        let mut v = SF::new();
        v.copy(&self.value);

        Self { value: v }
    }
}

pub struct Rsa2048DF {
    value: DF
}

impl BigFiniteField for Rsa2048DF {
    type BigInt = Rsa2048BIG;

    type DataType = DF;

    fn new() -> Self {
        Self{ value: DF::new()}
    }

    fn new_pow(x: isize, m: &Self) -> Self {
        let mut v = DF::new();
        v.power(x, &m.value);

        Self{ value: v }
    }

    fn new_copy(g: &Self) -> Self {
        let mut v = DF::new();
        v.copy(&g.value);

        Self{ value: v}
    }

    fn mul_mod(&mut self, y: &Self, p: &Self) {
        self.value = self.value.mul(&y.value).dmod(&p.value);
    }

    fn add(&mut self, g: &Self) {
        self.value.add(&g.value);
    }

    fn pow(&mut self, x: isize, m: &Self) {
        self.value.power(x, &m.value);
    }

    fn set(&mut self, g: &Self::DataType) {
        self.value.copy(g);
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut c = self.clone();
        let mut v:Vec<u8> = vec![0;MODBYTES];
        c.value.tobytes(&mut v);

        v
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() != 2*MODBYTES {
            panic!("Invalid length of field encoding");
        }

        let mut v = DF::new();
        v.frombytes(&bytes[0..MODBYTES - 1]);

        let mut m = DF::new();
        m.frombytes(&bytes[MODBYTES..MODBYTES*2 - 1]);

        Self { value: v }
    }

    fn equals(&self, g: &Self) -> bool {
        self.value.comp(&g.value) == 0
    }

    fn to_string(&self) -> String {
        self.value.tostring()
    }

    fn shr(&mut self) {
        self.value.shr();
    }
    fn shl(&mut self) {
        self.value.shl();
    }

    fn parity(&self) -> isize {
        let bts = self.to_bytes();
        let par =  bts.last().unwrap() % 2;
        return par as isize;
    }

    fn rmod(&mut self, p: &Self) {
        self.value.rmod(&p.value);
    }

    fn new_int(i: isize) -> Self {
        let mut t = DF::new();
        t.inc(i);
        Self{ value: t }
    }

}

impl Clone for Rsa2048DF {
    fn clone(&self) -> Self {
        let mut v = DF::new();
        v.copy(&self.value);

        Self { value: v }
    }
}

pub struct Rsa2048BIG {
    value: BIG
}

impl BigInt for Rsa2048BIG {
    type DataType = BIG;

    fn new() -> BigImpl {
        BigImpl::Rsa2048(Self { value: BIG::new() })
    }

    fn new_big(y: &BigImpl) -> BigImpl {
        if let BigImpl::Rsa2048(v) = y {
            BigImpl::Rsa2048(Self { value: BIG::new_big(&v.value)})
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn new_copy(y: &BigImpl) -> BigImpl {
        if let BigImpl::Rsa2048(v) = y {
            BigImpl::Rsa2048(Self { value:BIG::new_copy(&v.value) })
        } else {
            panic!("Incompatible big integer implementation!");
        }
        
    }

    fn new_ints(a: &[mcore::arch::Chunk]) -> BigImpl {
        BigImpl::Rsa2048(Self { value:BIG::new_ints(a) })
    }

    fn new_int(i: isize) -> BigImpl {
        BigImpl::Rsa2048(Self { value:BIG::new_int(i) })
    }

    fn new_rand(q: &BigImpl, rng: &mut impl RAND) -> BigImpl {
        if let BigImpl::Rsa2048(v) = q {
            BigImpl::Rsa2048(Self { value:BIG::randomnum(&v.value, rng) })
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn from_bytes(bytes: &[u8]) -> BigImpl {
        BigImpl::Rsa2048(Self { value:BIG::frombytes(bytes)})
    }

    fn rmod(&mut self, y: &BigImpl) {
        if let BigImpl::Rsa2048(v) = y {
            self.value.rmod(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn mul_mod(&mut self, y: &BigImpl, m: &BigImpl) {
        if let (BigImpl::Rsa2048(v), BigImpl::Rsa2048(w)) = (y, m) {
            self.value = BIG::mul(&self.value, &v.value).dmod(&w.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
        
    }

    fn add(&mut self, y: &BigImpl) {
        if let BigImpl::Rsa2048(v) = y {
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
        if let (BigImpl::Rsa2048(v), BigImpl::Rsa2048(w)) = (y, m) {
            self.value = self.value.powmod(&v.value, &w.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }
    }

    fn inv_mod(&mut self, m: &BigImpl) {
        if let BigImpl::Rsa2048(v) = m {
            self.value.invmodp(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }   
    }

    fn sub(&mut self, y: &BigImpl) {
        if let BigImpl::Rsa2048(v) = y {
            self.value.sub(&v.value);
        } else {
            panic!("Incompatible big integer implementation!");
        }  
    }

    fn imul(&mut self, i: isize) {
        self.value.imul(i);
    }

    fn equals(&self, y: &BigImpl) -> bool {
        if let BigImpl::Rsa2048(v) = y {
            BIG::comp(&self.value, &v.value) == 0
        } else {
            false
        }  
    }
}

impl Clone for Rsa2048BIG {
    fn clone(&self) -> Self {
        Self{ value: self.value.clone() }
    }
}