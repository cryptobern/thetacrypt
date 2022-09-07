use core::panic;
use std::mem::ManuallyDrop;
use crate::proto::scheme_types::Group;

use crate::{dl_schemes::{dl_groups::{bls12381::{Bls12381}, bn254::{Bn254}, ed25519::Ed25519}}, rand::RNG, interface::ThresholdCryptoError};
use crate::dl_schemes::bigint::BigImpl;

/*  Enum representing the implemented groups (incl. order and whether they support pairings). Each
    group has a code (8-bit unsigned integer) that's used to encode the group when serializing
    group elements. 

    TODO: change code to standard way of encoding EC groups */

impl Group {
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

    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Bls12381,
            1 => Self::Bn254,
            2 => Self::Ed25519,
            3 => Self::Rsa512,
            4 => Self::Rsa1024,
            5 => Self::Rsa2048,
            6 => Self::Rsa4096,
            _ => panic!("invalid code")
        }
    }

    pub fn get_order(&self) -> BigImpl {
        match self {
            Self::Bls12381 => Bls12381::get_order(),
            Self::Bn254 => Bn254::get_order(),
            Self::Ed25519 => Ed25519::get_order(),
            _ => panic!("not applicable")
        }
    }

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
}

/* GroupData holds the actual group element */
#[repr(C)]
pub union GroupData {
    pub bls12381: ManuallyDrop<Bls12381>,
    pub bn254: ManuallyDrop<Bn254>,
    pub ed25519: ManuallyDrop<Ed25519>,
}

/* GroupElement is the representation of a single group element */
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

impl GroupElement {
    pub fn cmp_group(&self, group: &Self) -> bool {
        self.group.eq(&group.group)
    } 

    pub fn is_type(&self, group: &Group) -> bool {
        self.group.eq(&group)
    }

    pub fn get_group(&self) -> Group {
        self.group.clone()
    }
    
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

    pub fn new_pow_big_ecp2(group: &Group, y: &BigImpl) -> Self {
        let data;

        match group {
            Group::Bls12381 => data = GroupData {bls12381:ManuallyDrop::new(Bls12381::new_pow_big_ecp2(y))},
            Group::Bn254 => data = GroupData {bn254:ManuallyDrop::new(Bn254::new_pow_big_ecp2(y))},
            _ => panic!("group does not support extensions")
        }

        Self { group: group.clone(), data: data}
    }

    pub fn init(group: &Group, data: GroupData) -> Self {
        Self {group:group.clone(), data}
    }

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


    /// self = self*y
    pub fn mul(&mut self, y: &Self) {
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
    
    /// self = self/y
    pub fn div(&mut self, y: &Self) {
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

    ///self = self^y
    pub fn pow(&mut self, y: &BigImpl) {       
        unsafe {
            match self.group {
                Group::Bls12381 => (*self.data.bls12381).pow(&y),
                Group::Bn254 => (*self.data.bn254).pow(&y),
                Group::Ed25519 => (*self.data.ed25519).pow(&y),
                _ => todo!()
            }
        }
    }

    pub fn get_order(&self) -> BigImpl {
        match self.group {
            Group::Bls12381 => Bls12381::get_order(),
            Group::Bn254 => Bn254::get_order(),
            Group::Ed25519 => Ed25519::get_order(),
            _ => todo!()
        }
        
    }

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