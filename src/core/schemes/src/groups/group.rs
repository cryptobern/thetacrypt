use core::panic;
use rasn::AsnType;
use std::borrow::Borrow;
use std::mem;
use std::{fmt::Debug, mem::ManuallyDrop};
use theta_derive::GroupOperations;

use theta_proto::scheme_types::Group;

use crate::integers::sizedint::SizedBigInt;
use crate::{
    groups::ec::{bls12381::Bls12381, bn254::Bn254, ed25519::Ed25519},
    interface::SchemeError,
    rand::RNG,
    scheme_types_impl::GroupDetails,
};

/*  Enum representing the implemented groups (incl. order and whether they support pairings) stored
in proto folder. Each group has a code (8-bit unsigned integer) that's used to encode the
group when serializing group elements.

TODO: change code to standard way of encoding EC groups */

/*  GroupElement is the representation of a single group element, use this for computation. It is a wrapper
   around the EC implementation Miracl Core provides to allow for curve-agnosic implementations of schemes.
*/
#[repr(C)]
#[rasn(enumerated)]
#[derive(Debug, Clone, AsnType, GroupOperations)]
pub enum GroupElement {
    Bls12381(Bls12381),
    Bn254(Bn254),
    Ed25519(Ed25519),
}

/*
    Objects of type GroupElement automatically implement the following trait thanks to procedural macros
*/
pub trait GroupOperations {
    /* return identity of given group */
    fn identity(group: &Group) -> Self;

    /* check whether two group elements belong to the same group */
    fn cmp_group(&self, other: &Self) -> bool;

    /* check whether group element belongs to certain group */
    fn is_type(&self, group: &Group) -> bool;

    /* get group from group element */
    fn get_group(&self) -> &Group;

    /* create new group element */
    fn new(group: &Group) -> Self;

    /* if the curve has an extension field, create element in extension field */
    fn new_ecp2(group: &Group) -> Self;

    /* calculate pairing between self and y (panics if group does not support pairings!) */
    fn pair(&self, y: &Self) -> Self;

    /* returns true if pair(x,y) == pair(z,w) (panics if group does not support pairings!)*/
    fn ddh(
        x: &GroupElement,
        y: &GroupElement,
        z: &GroupElement,
        w: &GroupElement,
    ) -> Result<bool, SchemeError>;

    /* generate a new group element from a hash (given as a byte array) -> not supported by ed25519! */
    fn new_hash(group: &Group, hash: &[u8]) -> Self;

    /* returns g^y where g is the generator of selected group */
    fn new_pow_big(group: &Group, y: &SizedBigInt) -> Self;

    /* returns g^y where g is the generator of the extension field of selected group */
    fn new_pow_big_ecp2(group: &Group, y: &SizedBigInt) -> Self;

    /* returns random element in group */
    fn new_rand(group: &Group, rng: &mut RNG) -> Self;

    /* returns self*y */
    fn mul(&self, y: &Self) -> Self;

    /* returns self/y */
    fn div(&self, y: &Self) -> Self;

    /* returns self^y */
    fn pow(&self, y: &SizedBigInt) -> Self;

    /* get order of group element */
    fn get_order(&self) -> SizedBigInt;

    /* encode group element in bytes (big endian) */
    fn to_bytes(&self) -> Vec<u8>;

    /* convert group element to hex string (big endian) */
    fn to_string(&self) -> String;

    /* decode group element from bytes (big endian) */
    fn from_bytes(bytes: &[u8], group: &Group, i: Option<u8>) -> Self;
}
