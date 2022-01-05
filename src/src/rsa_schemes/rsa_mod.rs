use super::bigint::BigInt;

use super::rsa_groups::rsa_domain::{RsaDomain, BigFiniteField};
use gmp_mpfr_sys::gmp;
use core::mem::MaybeUninit;

pub struct RsaModulus {
    p: BigInt,
    q: BigInt,
    n: BigInt,
    p1: BigInt,
    q1: BigInt,
    m: BigInt,
    c1: BigInt,
    c2: BigInt
}

impl Clone for RsaModulus {
    fn clone(&self) -> Self {
        Self { p: self.p.clone(), q: self.q.clone(), n: self.n.clone(), p1: self.p1.clone(), q1: self.q1.clone(), m: self.m.clone(), c1: self.c1.clone(), c2: self.c2.clone() }
    }
}

impl RsaModulus {
    pub fn new(p1: &BigInt, q1:&BigInt) -> Self {

        let mut p = p1.clone();
        let mut q = q1.clone();

        p.lshift(1);
        p.inc(1);

        q.lshift(1);
        p.inc(1);

        let n = BigInt::_mul(&p, &q);
        let m = BigInt::_mul(&p1, &q1);
        
        let mut _p = p.clone();
        let mut _q = q.clone();

        _p.inv_mod(&q);
        _q.inv_mod(&p);

        let c1 = BigInt::_mul(&p1, &p); 
        let c2 = BigInt::_mul(&q1, &q);     

        Self{p:p.clone(), q:q.clone(), n, p1:p1.clone(), q1:q1.clone(), m, c1, c2}
    }

    pub fn inv_n(&self, x: &BigInt) -> BigInt {
        /*
        let mut xp = BigInt::_inv_mod(&x, &self.p);
        let mut xq = BigInt::_inv_mod(&x, &self.q);

        xp.mul_mod(&self.c2, &self.n);
        xq.mul_mod(&self.c1, &self.n);
        
        let mut res = xp.clone();
        res.add(&xq);*/

        BigInt::_inv_mod(x, &self.n)
    }

    pub fn inv_m(&self, x: &BigInt) -> BigInt {
        /*
        let mut xp = BigInt::_inv_mod(&x, &self.p);
        let mut xq = BigInt::_inv_mod(&x, &self.q);

        xp.mul_mod(&self.c2, &self.n);
        xq.mul_mod(&self.c1, &self.n);
        
        let mut res = xp.clone();
        res.add(&xq);*/

        BigInt::_inv_mod(x, &self.m)
    }

    pub fn reduce(&self, x: &BigInt) -> BigInt {
        let mut res = x.clone();
        res.rmod(&self.n);
        res
    }   

    pub fn pow(&self, x: &BigInt, e: &BigInt) -> BigInt {
        let xp = BigInt::_pow_mod(x, e, &self.p);
        let xq = BigInt::_pow_mod(x, e, &self.q);

        self.crt(&xp, &xq)
    }

    pub fn mul(&self, x: &BigInt, y: &BigInt) -> BigInt {
        let mut res = x.clone();
        res.mul_mod(&y, &self.n);
        res
    }

    fn crt(&self, xp: &BigInt, xq: &BigInt) -> BigInt {
        let mut _xp = xp.clone();
        let mut _xq = xq.clone();

        _xp.mul_mod(&self.c2, &self.n);
        _xq.mul_mod(&self.c1, &self.n);
        
        let mut res = _xp.clone();
        res.add(&_xq);

        res
    }

    pub fn get_n(&self) -> BigInt {
        self.n.clone()
    }

    pub fn get_m(&self) -> BigInt { 
        self.m.clone() 
    }
}