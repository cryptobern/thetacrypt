use core::panic;
use rasn::AsnType;
use std::borrow::Borrow;
use std::mem;
use std::{fmt::Debug, mem::ManuallyDrop};
use theta_derive::GroupWrapper;

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

/* GroupElement is the representation of a single group element, use this for computation */
#[repr(C)]
#[rasn(enumerated)]
#[derive(Debug, Clone, AsnType, GroupWrapper)]
pub enum GroupElement {
    Bls12381(Bls12381),
    Bn254(Bn254),
    Ed25519(Ed25519),
}

impl PartialEq for GroupElement {
    fn eq(&self, other: &Self) -> bool {
        if mem::discriminant(self) != mem::discriminant(other) {
            return false;
        }

        match self {
            Self::Bls12381(x) => {
                if let Self::Bls12381(y) = other {
                    return x.eq(y);
                }
            }
            Self::Bn254(x) => {
                if let Self::Bn254(y) = other {
                    return x.eq(y);
                }
            }
            Self::Ed25519(x) => {
                if let Self::Ed25519(y) = other {
                    return x.eq(y);
                }
            }
            _ => {
                return false;
            }
        }

        return false;
    }
}

// TODO: create macro to simplify match clauses

// GroupElement represents a particular element in a group
impl GroupElement {
    /* return identity of given group */
    pub fn identity(group: &Group) -> GroupElement {
        match group {
            Group::Bls12381 => Self::Bls12381(Bls12381::identity()),
            Group::Bn254 => Self::Bn254(Bn254::identity()),
            Group::Ed25519 => Self::Ed25519(Ed25519::identity()),
            _ => todo!(),
        }
    }

    /* check whether two group elements belong to the same group */
    pub fn cmp_group(&self, other: &Self) -> bool {
        mem::discriminant(self) == mem::discriminant(other)
    }

    /* check whether group element belongs to certain group */
    pub fn is_type(&self, group: &Group) -> bool {
        match group {
            Group::Bls12381 => {
                if let Self::Bls12381(x) = self {
                    return true;
                }
            }
            Group::Ed25519 => {
                if let Self::Ed25519(x) = self {
                    return true;
                }
            }
            Group::Bn254 => {
                if let Self::Bn254(x) = self {
                    return true;
                }
            }
            _ => todo!(),
        }

        return false;
    }

    /* get group from group element */
    pub fn get_group(&self) -> &Group {
        match self {
            Self::Bls12381(x) => &Group::Bls12381,
            Self::Ed25519(x) => &Group::Ed25519,
            Self::Bn254(x) => &Group::Bn254,
            _ => todo!(),
        }
    }

    /* create new group element */
    pub fn new(group: &Group) -> Self {
        match group {
            Group::Bls12381 => Self::Bls12381(Bls12381::new()),
            Group::Ed25519 => Self::Ed25519(Ed25519::new()),
            Group::Bn254 => Self::Bn254(Bn254::new()),
            _ => todo!(),
        }
    }

    // if the curve has an extension field, create element in extension field
    pub fn new_ecp2(group: &Group) -> Self {
        match group {
            Group::Bls12381 => Self::Bls12381(Bls12381::new_ecp2()),
            Group::Bn254 => Self::Bn254(Bn254::new_ecp2()),
            _ => panic!("group does not support pairings"),
        }
    }

    /* calculate pairing between self and y */
    pub fn pair(&self, y: &GroupElement) -> GroupElement {
        if !self.get_group().supports_pairings() {
            panic!("group does not support pairings");
        }

        if !self.cmp_group(&y) {
            panic!("incompatible groups");
        }

        match self {
            Self::Bls12381(_x) => {
                if let Self::Bls12381(_y) = y {
                    return Self::Bls12381(Bls12381::pair(_x, _y).unwrap());
                }
            }
            Self::Bn254(_x) => {
                if let Self::Bn254(_y) = y {
                    return Self::Bn254(Bn254::pair(_x, _y).unwrap());
                }
            }
            _ => {
                panic!()
            }
        }

        panic!()
    }

    /* returns true if pair(x,y) == pair(z,w) */
    pub fn ddh(
        x: &GroupElement,
        y: &GroupElement,
        z: &GroupElement,
        w: &GroupElement,
    ) -> Result<bool, SchemeError> {
        if !x.get_group().supports_pairings() {
            panic!("group does not support pairings");
        }

        if !x.cmp_group(&y) || !y.cmp_group(&z) || !z.cmp_group(&w) {
            panic!("incompatible groups");
        }

        match x {
            Self::Bls12381(_x) => {
                if let Self::Bls12381(_y) = y {
                    if let Self::Bls12381(_z) = z {
                        if let Self::Bls12381(_w) = w {
                            return Bls12381::ddh(&_x, &_y, &_z, &_w);
                        }
                    }
                }
            }
            Self::Bn254(_x) => {
                if let Self::Bn254(_y) = y {
                    if let Self::Bn254(_z) = z {
                        if let Self::Bn254(_w) = w {
                            return Bn254::ddh(&_x, &_y, &_z, &_w);
                        }
                    }
                }
            }
            _ => {
                panic!()
            }
        }

        panic!()
    }

    /* generate a new group element from a hash (given as a byte array) */
    pub fn new_hash(group: &Group, hash: &[u8]) -> Self {
        match group {
            Group::Bls12381 => {
                return Self::Bls12381(Bls12381::new_from_ecp(
                    mcore::bls12381::bls::bls_hash_to_point(hash),
                ));
            }
            Group::Bn254 => {
                return Self::Bn254(Bn254::new_from_ecp(mcore::bn254::bls::bls_hash_to_point(
                    hash,
                )));
            }
            _ => panic!("group does not support hash to point"),
        }
    }

    /* returns g^y where g is the generator of selected group */
    pub fn new_pow_big(group: &Group, y: &SizedBigInt) -> Self {
        match group {
            Group::Bls12381 => {
                return Self::Bls12381(Bls12381::new_pow_big(y));
            }
            Group::Bn254 => {
                return Self::Bn254(Bn254::new_pow_big(y));
            }
            Group::Ed25519 => {
                return Self::Ed25519(Ed25519::new_pow_big(y));
            }
            _ => todo!(),
        }
    }

    /* returns g^y where g is the generator of the extension field of selected group */
    pub fn new_pow_big_ecp2(group: &Group, y: &SizedBigInt) -> Self {
        match group {
            Group::Bls12381 => {
                return Self::Bls12381(Bls12381::new_pow_big_ecp2(y));
            }
            Group::Bn254 => {
                return Self::Bn254(Bn254::new_pow_big_ecp2(y));
            }
            _ => panic!("group does not support extensions"),
        }
    }

    /* returns random element in group */
    pub fn new_rand(group: &Group, rng: &mut RNG) -> Self {
        match group {
            Group::Bls12381 => {
                return Self::Bls12381(Bls12381::new_rand(rng));
            }
            Group::Bn254 => {
                return Self::Bn254(Bn254::new_rand(rng));
            }
            Group::Ed25519 => {
                return Self::Ed25519(Ed25519::new_rand(rng));
            }
            _ => todo!(),
        }
    }

    /* returns self*y */
    pub fn mul(&self, y: &Self) -> Self {
        if !Self::cmp_group(&self, y) {
            panic!("incompatible groups!");
        }

        match self {
            Self::Bls12381(_x) => {
                if let Self::Bls12381(_y) = y {
                    return _x.mul(_y);
                }
            }
            Self::Bn254(_x) => {
                if let Self::Bn254(_y) = y {
                    return _x.mul(_y);
                }
            }
            Self::Ed25519(_x) => {
                if let Self::Ed25519(_y) = y {
                    return _x.mul(_y);
                }
            }
            _ => todo!(),
        }

        panic!("incompatible groups");
    }

    /* returns self/y */
    pub fn div(&self, y: &Self) -> Self {
        if !Self::cmp_group(&self, y) {
            panic!("incompatible groups!");
        }

        match self {
            Self::Bls12381(_x) => {
                if let Self::Bls12381(_y) = y {
                    return _x.div(_y);
                }
            }
            Self::Bn254(_x) => {
                if let Self::Bn254(_y) = y {
                    return _x.div(_y);
                }
            }
            Self::Ed25519(_x) => {
                if let Self::Ed25519(_y) = y {
                    return _x.div(_y);
                }
            }
            _ => todo!(),
        }

        panic!("incompatible groups");
    }

    /* returns self^y */
    pub fn pow(&self, y: &SizedBigInt) -> Self {
        match self {
            Self::Bls12381(_x) => {
                return _x.pow(y);
            }
            Self::Bn254(_x) => {
                return _x.pow(y);
            }
            Self::Ed25519(_x) => {
                return _x.pow(y);
            }
            _ => todo!(),
        }
    }

    /* get order of group element */
    pub fn get_order(&self) -> SizedBigInt {
        match self {
            Self::Bls12381(_) => Bls12381::get_order(),
            Self::Bn254(_) => Bn254::get_order(),
            Self::Ed25519(_) => Ed25519::get_order(),
            _ => todo!(),
        }
    }

    /* encode group element in bytes */
    pub fn to_bytes(&self) -> Vec<u8> {
        unsafe {
            match self {
                Self::Bls12381(_x) => _x.to_bytes(),
                Self::Bn254(_x) => _x.to_bytes(),
                Self::Ed25519(_x) => _x.to_bytes(),
                _ => todo!(),
            }
        }
    }

    /* convert group element to hex string */
    pub fn to_string(&self) -> String {
        unsafe {
            match self {
                Self::Bls12381(_x) => _x.to_string(),
                Self::Bn254(_x) => _x.to_string(),
                Self::Ed25519(_x) => _x.to_string(),
                _ => todo!(),
            }
        }
    }

    /* decode group element from bytes */
    pub fn from_bytes(bytes: &[u8], group: &Group, i: Option<u8>) -> Self {
        let mut j = 0;
        if i.is_some() {
            j = i.unwrap();
        }

        match group {
            Group::Bls12381 => return Self::Bls12381(Bls12381::from_bytes(bytes, j)),
            Group::Bn254 => return Self::Bn254(Bn254::from_bytes(bytes, j)),
            Group::Ed25519 => return Self::Ed25519(Ed25519::from_bytes(bytes)),
            _ => todo!(),
        }
    }
}
