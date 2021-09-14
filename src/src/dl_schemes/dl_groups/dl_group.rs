use mcore::{rand::RAND};
use crate::bigint::*;

pub trait DlGroup: 
    Sized 
    + Clone
    + 'static {
    type BigInt: BigInt;
    type DataType;

    /// returns new element initialized with generator of the group
    fn new() -> Self;                          

    /// Returns a new group element initialized with generator^x.
    fn new_pow_big(x: &BigImpl) -> Self;     

    /// returns random element in group
    fn new_rand(rng: &mut impl RAND) -> Self;   

    /// creates a copy of a group element
    fn new_copy(g: &Self) -> Self;

    /// self = self*g
    fn mul(&mut self, g: &Self);                

    ///self = self^x
    fn pow(&mut self, x: &BigImpl);             

    /// self = self/g
    fn div(&mut self, g: &Self);                

    /// self = g
    fn set(&mut self, g: &Self::DataType);     

    /// serialize to bytes
    fn to_bytes(&self) -> Vec<u8>;              

    /// load from bytes 
    fn from_bytes(bytes: &[u8]) -> Self;         

    /// check whether two elements are equal
    fn equals(&self, g: &Self) -> bool;         

    /// returns order of the group
    fn get_order() -> BigImpl; 

    /// wrap bigint type in bigimpl
    fn wrp(x: &Self::BigInt) -> BigImpl;        

    /// get number of bytes
    fn nbytes() -> usize;                      

    /// convert group element to string representation
    fn to_string(&self) -> String;

    fn get_name() -> String;
}