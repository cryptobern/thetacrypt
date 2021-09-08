use mcore::{arch::Chunk, rand::RAND};

use crate::dl_schemes::dl_groups::BigImpl;

// Wrapper class for the different BIG implementations in Miracl Core
pub trait BigInt: 
    Sized 
    + Clone
    + 'static {
    type DataType;

    fn new() -> BigImpl;
    fn new_big(y: &BigImpl) -> BigImpl;
    fn new_ints(a: &[Chunk]) -> BigImpl;
    fn new_int(i: isize) -> BigImpl;
    fn new_copy(y: &BigImpl) -> BigImpl;
    fn new_rand(q: &BigImpl, rng: &mut impl RAND) -> BigImpl;
    fn from_bytes(bytes: &[u8]) -> BigImpl;
    fn rmod(&mut self, y: &BigImpl);
    fn mul_mod(&mut self, y: &BigImpl, m: &BigImpl);
    fn inv_mod(&mut self, m: &BigImpl);
    fn add(&mut self, y: &BigImpl);
    fn sub(&mut self, y: &BigImpl);
    fn imul(&mut self, i: isize);
    fn pow_mod(&mut self, y: &BigImpl, m: &BigImpl);
    fn to_bytes(&self) -> Vec<u8>;
    fn to_string(&self) -> String;
    fn equals(&self, y: &BigImpl) -> bool;
}