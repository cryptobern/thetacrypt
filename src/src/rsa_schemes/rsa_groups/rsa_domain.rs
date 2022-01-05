use mcore::{rand::RAND};
use crate::bigint::*;

pub trait RsaDomain: 
    Sized 
    + Clone
    + 'static {
    type BigInt: BigInt;
    type DataType;
    type DF: BigFiniteField;

    /// returns new element initialized with generator of the field
    /// m: modulus
    fn new() -> Self;                          

    /// Returns a new field element initialized with generator^x.
    fn new_pow(x: &Self, m: &Self) -> Self;     

    /// returns random element in field
    fn new_rand(rng: &mut impl RAND, len: usize) -> Self;   

    fn new_prime(rng: &mut impl RAND, len:usize) -> Self;

    fn new_int(i: isize) -> Self;

    fn rand(&mut self, rng: &mut impl RAND, len: usize);

    /// creates a copy of a field element
    fn new_copy(y: &Self) -> Self;

    /// self = self*y
    fn mul(&self, y: &Self) -> Self::DF;   

    fn _mul(x: &Self, y: &Self) -> Self::DF {
        let z = x.clone();
        z.mul(y)
    }

    fn mul_mod(&mut self, y: &Self, p: &Self);
    
    /// self = self + y
    fn add(&mut self, y: &Self);  

    fn _add(x: &Self, y: &Self) -> Self {
        let mut z = x.clone();
        z.add(y);
        z
    }

    fn sub(&mut self, y: &Self);

    fn _sub(x: &Self, y: &Self) -> Self {
        let mut z = x.clone();
        z.sub(y);
        z
    }

    ///self = self^x mod m
    fn pow(&mut self, x: &Self, m: &Self);  

    fn _pow(x: &Self, y: &Self, m: &Self) -> Self {
        let mut z = x.clone();
        z.pow(y, m);
        z
    }

    /// self = self/g
    fn invmodp(&mut self, p: &Self);                

    /// self = g
    fn set(&mut self, y: &Self::DataType);     

    /// serialize to bytes
    fn to_bytes(&self) -> Vec<u8>;              

    /// load from bytes 
    fn from_bytes(bytes: &mut [u8]) -> Self;  

    /// check whether two elements are equal
    fn equals(&self, y: &Self) -> bool;                              

    /// convert field element to string representation
    fn to_string(&self) -> String;

    fn is_prime(&self, rng: &mut impl RAND) -> bool;

    fn last_bits(&mut self, n: usize) -> isize;

    fn inc(&mut self, i: isize);

    fn dec(&mut self, i: isize);

    fn copy(&mut self, y: &Self);

    fn inv_mod_p_q(x: &Self, p: &Self, q: &Self) -> (Self, Self) {
        /* 
        let x_inv_p = x;
        p.clone();
        let mut x_mod_p = Self::dmod(x, p);
        let mut x_mod_q = Self::dmod(x, q);

        x_mod_p.invmodp(p);
        x_mod_q.invmodp(q);

        let mut p_inv = p.clone();
        let mut q_inv = q.clone();
        p_inv.invmodp(q);
        q_inv.invmodp(p);

        let res = p_inv;
        p_inv.mul_mod(q);
        res.mul()*/

        let mut dp = x.clone();
        let mut dq = x.clone();
        dp.invmodp(p);
        dq.invmodp(q);

        (dp, dq)
    }

    fn dmod(x: &mut Self::DF, p: &Self) -> Self;

    fn cfactor(&self, x: isize) -> bool;

    fn shr(&mut self);
    fn shl(&mut self);

    fn parity(&self) -> isize;
    fn norm(&mut self);

    fn rmod(&mut self, p: &Self);

    fn _rmod(x: &Self, y:&Self) -> Self {
        let mut tmp = x.clone();
        tmp.rmod(&y);
        tmp
    }

    fn jacobi(&self, x: &Self::DF) -> i8;

    fn equals_int(&self, i: isize) -> bool {
        self.equals(&Self::new_int(i))
    }

    fn to_df(&self) -> Self::DF {
        Self::_mul(&self, &Self::new_int(1))
    }
}

pub trait BigFiniteField: 
    Sized 
    + Clone
    + 'static {
    type BigInt: BigInt;
    type DataType;

    /// returns new element initialized with generator of the field
    fn new() -> Self;      

    fn new_int(i: isize) -> Self;

    /// Returns a new field element initialized with generator^x.
    fn new_pow(x: isize, m: &Self) -> Self;      

    /// creates a copy of a field element
    fn new_copy(g: &Self) -> Self;

    /// self = self*y mod m
    fn mul_mod(&mut self, y: &Self, m: &Self);   
    
    /// self = self + g
    fn add(&mut self, g: &Self);  

    ///self = self^x
    fn pow(&mut self, x: isize, m: &Self);                            

    /// self = g
    fn set(&mut self, g: &Self::DataType);     

    fn rmod(&mut self, p: &Self);

    /// serialize to bytes
    fn to_bytes(&self) -> Vec<u8>;              

    /// load from bytes 
    fn from_bytes(bytes: &[u8]) -> Self;         

    /// check whether two elements are equal
    fn equals(&self, g: &Self) -> bool;   
    
    fn equals_int(&self, i: isize) -> bool {
        self.equals(&Self::new_int(i))
    }

    /// convert field element to string representation
    fn to_string(&self) -> String;

    fn parity(&self) -> isize;

    fn shr(&mut self);
    fn shl(&mut self);
}

