
use mcore::{rand::RAND};
use crate::bigint::BigInt;

use super::BigImpl;

pub trait DlGroup: 
    Sized 
    + Clone
    + 'static {
    type BigInt: BigInt;
    type DataType;

    fn new() -> Self;                           // returns generator
    fn new_pow_big(x: &BigImpl) -> Self;        // returns generator^x
    fn new_rand(rng: &mut impl RAND) -> Self;   // returns random element in group
    fn new_copy(g: &Self) -> Self;
    fn mul(&mut self, g: &Self);                // self = self*g
    fn pow(&mut self, x: &BigImpl);             // self = self^x
    fn div(&mut self, g: &Self);                // self = self/g
    fn set(&mut self, g: &Self::DataType);      // self = g
    fn to_bytes(&self) -> Vec<u8>;               // serialize to bytes
    fn from_bytes(&self, bytes: &[u8]);         // load from bytes 
    fn equals(&self, g: &Self) -> bool;         // check whether two elements are equal
    fn get_order() -> BigImpl; 
    fn wrp(x: &Self::BigInt) -> BigImpl;        // wrap bigint type in bigimpl
    fn nbytes() -> usize;                       // get number of bytes
}