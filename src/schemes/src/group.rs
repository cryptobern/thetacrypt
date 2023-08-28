use core::{panic, fmt};
use std::{fmt::Debug, mem::ManuallyDrop};
use rasn::AsnType;

use thetacrypt_proto::scheme_types::GroupCode;

use crate::{dl_schemes::dl_groups::{bls12381::Bls12381, bn254::Bn254, ed25519::Ed25519}, rand::RNG, interface::ThresholdCryptoError, group_generators};
use crate::dl_schemes::bigint::BigImpl;

/*  Enum representing the implemented groups (incl. order and whether they support pairings). Each
    group has a code (8-bit unsigned integer) that's used to encode the group when serializing
    group elements.

    TODO: change code to standard way of encoding EC groups */


// Group represents the description of a group and contains information about its order, whether it
// supports pairings etc. It is not used to store values or for computation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Group {
    Bls12381 = GroupCode::Bls12381 as isize,
    Bn254  = GroupCode::Bn254 as isize,
    Ed25519 = GroupCode::Ed25519 as isize,
    Rsa512  = GroupCode::Rsa512  as isize,
    Rsa1024 = GroupCode::Rsa1024 as isize,
    Rsa2048 = GroupCode::Rsa2048 as isize,
    Rsa4096 = GroupCode::Rsa4096 as isize,

}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bls12381 => write!(f, "Bls12381"),
            Self::Bn254 => write!(f, "Bn254"),
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::Rsa512 => write!(f, "Rsa512"),
            Self::Rsa1024 => write!(f, "Rsa1024"),
            Self::Rsa2048 => write!(f, "Rsa2048"),
            Self::Rsa4096 => write!(f, "Rsa4096"),
        }
    }
}

impl Group {
    /* returns whether the group is a discrete logarithm group */
    pub fn is_dl(&self) -> bool {
        match self {
            Self::Bls12381 => true,
            Self::Bn254 => true,
            Self::Ed25519 => true,
            Self::Rsa512 => false,
            Self::Rsa1024 => false,
            Self::Rsa2048 => false,
            Self::Rsa4096 => false,
        }
    }

    /* returns group identifier */
    pub fn get_code(&self) -> u8 {
        match self {
            Self::Bls12381 => 0,
            Self::Bn254 => 1,
            Self::Ed25519 => 2,
            Self::Rsa512 => 3,
            Self::Rsa1024 => 3,
            Self::Rsa2048 => 4,
            Self::Rsa4096 => 5,
        }
    }

    pub fn from_code(code: u8) -> Result<Self, ThresholdCryptoError> {
        match code {
            0 => Ok(Self::Bls12381),
            1 => Ok(Self::Bn254),
            2 => Ok(Self::Ed25519),
            3 => Ok(Self::Rsa512),
            4 => Ok(Self::Rsa1024),
            5 => Ok(Self::Rsa2048),
            6 => Ok(Self::Rsa4096),
            _ => Err(ThresholdCryptoError::UnknownGroup)
        }
    }

    pub fn parse_string(name: &str) -> Result<Self, ThresholdCryptoError> {
        match name {
            "bls12381" => Ok(Self::Bls12381),
            "bn254" => Ok(Self::Bn254),
            "ed25519" => Ok(Self::Ed25519),
            "rsa512" => Ok(Self::Rsa512),
            "rsa1024" => Ok(Self::Rsa1024),
            "rsa2048" => Ok(Self::Rsa2048),
            "rsa4096" => Ok(Self::Rsa4096),
            _ => Err(ThresholdCryptoError::UnknownGroupString)
        }
    }

    /* returns the group order */
    pub fn get_order(&self) -> BigImpl {
        match self {
            Self::Bls12381 => Bls12381::get_order(),
            Self::Bn254 => Bn254::get_order(),
            Self::Ed25519 => Ed25519::get_order(),
            _ => panic!("not applicable")
        }
    }

    /* returns whether the group supports pairings */
    pub fn supports_pairings(&self) -> bool {
        match self {
            Self::Bls12381 => true,
            Self::Bn254 => true,
            Self::Ed25519 => false,
            Self::Rsa512 => false,
            Self::Rsa1024 => false,
            Self::Rsa2048 => false,
            Self::Rsa4096 => false,
        }
    }

    // Get a group element that can serve as alternate group generator
    // for the this cyclic group.
    pub fn get_alternate_generator(&self) -> GroupElement {
        match self {
            Self::Bls12381 => GroupElement::from_bytes(&group_generators::BLS12381_ALTERNATE_GENERATOR_BYTES, &self, None),
            Self::Bn254 => GroupElement::from_bytes(&group_generators::BN254_ALTERNATE_GENERATOR_BYTES, &self, None),
            _ => panic!("no alternate generator available")
        }
    }
}

/* GroupData holds the actual group element data, do not use this for computation */
#[repr(C)]
pub union GroupData {
    pub bls12381: ManuallyDrop<Bls12381>,
    pub bn254: ManuallyDrop<Bn254>,
    pub ed25519: ManuallyDrop<Ed25519>,
}

impl Debug for GroupData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupData").finish_non_exhaustive()
    }
}

/* GroupElement is the representation of a single group element, use this for computation */
#[derive(Debug, AsnType)]
pub struct GroupElement {
    group: Group,
    data: GroupData
}

impl PartialEq for GroupElement {
    fn eq(&self, other: &Self) -> bool {
        if self.group != other.group {
            return false;
        }
        unsafe {
            match self.group {
                Group::Bls12381 => (*self.data.bls12381).eq(&other.data.bls12381),
                Group::Bn254 => (*self.data.bn254).eq(&other.data.bn254),
                Group::Ed25519 => (*self.data.ed25519).eq(&other.data.ed25519),
                _ => todo!()
            }
        }
    }
}

impl Clone for GroupElement {
    fn clone(&self) -> Self {
        unsafe {
            match self.group {
                Group::Bls12381 => {
                    GroupElement { group:self.group.clone(), data: GroupData {bls12381:self.data.bls12381.clone()} }
                },
                Group::Bn254 => {
                    GroupElement { group:self.group.clone(), data: GroupData {bn254:self.data.bn254.clone()} }
                },
                Group::Ed25519 => {
                    GroupElement { group:self.group.clone(), data: GroupData {ed25519:self.data.ed25519.clone()} }
                },
                _ => {
                    todo!();
                }
            }
        }
    }
}


// TODO: create macro to simplify match clauses

// GroupElement represents a particular element in a group
impl GroupElement {
    /* construct group element out of group object and data */
    pub fn create(group: Group, data: GroupData) -> Self {
        Self {group, data}
    }

    /* return identity of given group */
    pub fn identity(group: &Group) -> GroupElement {
        let data;
        match group {
            Group::Bls12381 => data = GroupData {bls12381:ManuallyDrop::new(Bls12381::identity())},
            Group::Bn254 => data = GroupData {bn254:ManuallyDrop::new(Bn254::identity())},
            Group::Ed25519 => data = GroupData {ed25519:ManuallyDrop::new(Ed25519::identity())},
            _ => todo!()
        }

        Self { group:group.clone(), data }
    }

    /* check whether two group elements belong to the same group */
    pub fn cmp_group(&self, group: &Self) -> bool {
        self.group.eq(&group.group)
    }

    /* check whether group element belongs to certain group */
    pub fn is_type(&self, group: &Group) -> bool {
        self.group.eq(&group)
    }

    /* get group from group element */
    pub fn get_group(&self) -> &Group {
        &self.group
    }
    
    /* create new group element */
    pub fn new(group: &Group) -> Self {
        let data;

        match group {
            Group::Bls12381 => data = GroupData {bls12381:ManuallyDrop::new(Bls12381::new())},
            Group::Bn254 => data = GroupData {bn254:ManuallyDrop::new(Bn254::new())},
            Group::Ed25519 => data = GroupData {ed25519:ManuallyDrop::new(Ed25519::new())},
            _ => todo!()
        }

        Self { group: group.clone(), data: data}
    }

    // if the curve has an extension field, create element in extension field
    pub fn new_ecp2(group: &Group) -> Self {
        let data;

        match group {
            Group::Bls12381 => data = GroupData {bls12381:ManuallyDrop::new(Bls12381::new_ecp2())},
            Group::Bn254 => data = GroupData {bn254:ManuallyDrop::new(Bn254::new_ecp2())},
            _ => panic!("group does not support pairings")
        }

        Self { group: group.clone(), data: data}
    }

    /* calculate pairing between self and y */
    pub fn pair(&self, y: &GroupElement) -> GroupElement {
        if !self.get_group().supports_pairings() {
            panic!("group does not support pairings");
        }

        if !self.cmp_group(&y) {
            panic!("incompatible groups");
        }

        unsafe {
            match self.get_group() {
                Group::Bls12381 => {
                    let res = Bls12381::pair(&self.data.bls12381, &y.data.bls12381).unwrap();
                    GroupElement { group:Group::Bls12381, data:GroupData { bls12381: ManuallyDrop::new(res) }}
                },
                Group::Bn254 => {
                    let res = Bn254::pair(&self.data.bn254, &y.data.bn254).unwrap();
                    GroupElement { group:Group::Bn254, data:GroupData { bn254: ManuallyDrop::new(res) }}
                },
                _ => {panic!()}
            }
        }
    }

    /* returns true if pair(x,y) == pair(z,w) */
    pub fn ddh(x: &GroupElement, y: &GroupElement, z: &GroupElement, w: &GroupElement) -> Result<bool, ThresholdCryptoError> {
        if !x.get_group().supports_pairings() {
            panic!("group does not support pairings");
        }

        if !x.cmp_group(&y) || !y.cmp_group(&z) || !z.cmp_group(&w){
            panic!("incompatible groups");
        }

        unsafe {
            match x.get_group() {
                Group::Bls12381 => {
                    Bls12381::ddh(&x.data.bls12381, &y.data.bls12381, &z.data.bls12381, &w.data.bls12381)
                },
                Group::Bn254 => {
                    Bn254::ddh(&x.data.bn254, &y.data.bn254, &z.data.bn254, &w.data.bn254)
                },
                _ => {panic!()}
            }
        }
    }

    /* generate a new group element from a hash (given as a byte array) */
    pub fn new_hash(group: &Group, hash: &[u8]) -> Self {
        let data;

        match group {
            Group::Bls12381 => data = GroupData { bls12381:ManuallyDrop::new(Bls12381::new_from_ecp(mcore::bls12381::bls::bls_hash_to_point(hash))) },
            Group::Bn254 => data = GroupData { bn254:ManuallyDrop::new(Bn254::new_from_ecp(mcore::bn254::bls::bls_hash_to_point(hash))) },
            _ => panic!("group does not support hash to point")
        }

        Self { group: group.clone(), data: data }
    }

    /* returns g^y where g is the generator of selected group */
    pub fn new_pow_big(group: &Group, y: &BigImpl) -> Self {
        let data;

        match group {
            Group::Bls12381 => data = GroupData {bls12381:ManuallyDrop::new(Bls12381::new_pow_big(y))},
            Group::Bn254 => data = GroupData {bn254:ManuallyDrop::new(Bn254::new_pow_big(y))},
            Group::Ed25519 => data = GroupData {ed25519:ManuallyDrop::new(Ed25519::new_pow_big(y))},
            _ => todo!()
        }

        Self { group: group.clone(), data: data}
    }

    /* returns g^y where g is the generator of the extension field of selected group */
    pub fn new_pow_big_ecp2(group: &Group, y: &BigImpl) -> Self {
        let data;

        match group {
            Group::Bls12381 => data = GroupData {bls12381:ManuallyDrop::new(Bls12381::new_pow_big_ecp2(y))},
            Group::Bn254 => data = GroupData {bn254:ManuallyDrop::new(Bn254::new_pow_big_ecp2(y))},
            _ => panic!("group does not support extensions")
        }

        Self { group: group.clone(), data: data}
    }

    /* initialize group element */
    pub fn init(group: &Group, data: GroupData) -> Self {
        Self {group:group.clone(), data}
    }

    /* returns random element in group */
    pub fn new_rand(group: &Group, rng: &mut RNG) -> Self {
        let data;

        match group {
            Group::Bls12381 => data = GroupData {bls12381:ManuallyDrop::new(Bls12381::new_rand(rng))},
            Group::Bn254 => data = GroupData {bn254:ManuallyDrop::new(Bn254::new_rand(rng))},
            Group::Ed25519 => data = GroupData {ed25519:ManuallyDrop::new(Ed25519::new_rand(rng))},
            _ => todo!()
        }

        Self { group: group.clone(), data: data}
    }


    /* returns self*y */
    pub fn mul(&self, y: &Self) -> Self{
        if self.group != y.group {
            panic!("incompatible groups!");
        }

        unsafe {
            match self.group {
                Group::Bls12381 => (*self.data.bls12381).mul(&(*y.data.bls12381)),
                Group::Bn254 => (*self.data.bn254).mul(&(*y.data.bn254)),
                Group::Ed25519 => (*self.data.ed25519).mul(&(*y.data.ed25519)),
                _ => todo!()
            }
        }
    }  
    
    /* returns self/y */
    pub fn div(&self, y: &Self) -> Self {
        if self.group != y.group {
            panic!("incompatible groups!");
        }

        unsafe {
            match self.group {
                Group::Bls12381 => (*self.data.bls12381).div(&(*y.data.bls12381)),
                Group::Bn254 => (*self.data.bn254).div(&(*y.data.bn254)),
                Group::Ed25519 => (*self.data.ed25519).div(&(*y.data.ed25519)),
                _ => todo!()
            }
        }
    }

   /* returns self^y */
    pub fn pow(&self, y: &BigImpl) -> Self {       
        unsafe {
            match self.group {
                Group::Bls12381 => (*self.data.bls12381).pow(&y),
                Group::Bn254 => (*self.data.bn254).pow(&y),
                Group::Ed25519 => (*self.data.ed25519).pow(&y),
                _ => todo!()
            }
        }
    }

    /* get order of group element */
    pub fn get_order(&self) -> BigImpl {
        match self.group {
            Group::Bls12381 => Bls12381::get_order(),
            Group::Bn254 => Bn254::get_order(),
            Group::Ed25519 => Ed25519::get_order(),
            _ => todo!()
        }

    }

    /* encode group element in bytes */
    pub fn to_bytes(&self) -> Vec<u8> {       
        unsafe {
            match self.group {
                Group::Bls12381 => (*self.data.bls12381).to_bytes(),
                Group::Bn254 => (*self.data.bn254).to_bytes(),
                Group::Ed25519 => (*self.data.ed25519).to_bytes(),
                _ => todo!()
            }
        }
    }

    /* convert group element to hex string */
    pub fn to_string(&self) -> String {       
        unsafe {
            match self.group {
                Group::Bls12381 => (*self.data.bls12381).to_string(),
                Group::Bn254 => (*self.data.bn254).to_string(),
                Group::Ed25519 => (*self.data.ed25519).to_string(),
                _ => todo!()
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
            Group::Bls12381 => Self { group:group.clone(), data:GroupData {bls12381:ManuallyDrop::new(Bls12381::from_bytes(bytes, j))}},
            Group::Bn254 => Self { group:group.clone(), data:GroupData {bn254:ManuallyDrop::new(Bn254::from_bytes(bytes, j))}},
            Group::Ed25519 => Self { group:group.clone(), data:GroupData {ed25519:ManuallyDrop::new(Ed25519::from_bytes(bytes))}},
            _ => todo!()
        }
    }
}