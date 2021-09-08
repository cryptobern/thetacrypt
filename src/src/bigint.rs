use mcore::{arch::Chunk, rand::RAND};

use crate::dl_schemes::dl_groups::BigImpl;


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
    fn add(&mut self, y: &BigImpl);
    fn pow_mod(&mut self, y: &BigImpl, m: &BigImpl);
    fn to_bytes(&self) -> Vec<u8>;
    fn to_string(&self) -> String;
}