use std::mem::ManuallyDrop;

use rasn::Encode;

use crate::{dl_schemes::{bigint::*, DlDomain}, rand::RNG, interface::Serializable};

use super::{bls12381::{Bls12381, Bls12381ECP2, Bls12381FP12}, bn254::{Bn254, Bn254ECP2, Bn254FP12}, ed25519::Ed25519};

pub trait DlGroup: 
    Sized 
    + Clone
    + PartialEq
    + Serializable
    + 'static {
    type BigInt: BigInt;
    type DataType;

    /// returns new element initialized with generator of the group
    fn new() -> Self;                          

    /// Returns a new group element initialized with generator^x.
    fn new_pow_big(x: &BigImpl) -> Self;     

    /// returns random element in group
    fn new_rand(rng: &mut RNG) -> Self;   

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Group {
    BLS12381,
    BN254,
    ED25519,
    RSA
}

impl Group {
    pub fn get_code(&self) -> u8 {
        match self {
            Bls12381 => 0,
            BN254 => 1,
            Ed25519 => 2
        }
    }

    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::BLS12381,
            1 => Self::BN254,
            2 => Self::ED25519,
            _ => panic!("invalid code")
        }
    }

    pub fn get_order(&self) -> BigImpl {
        match self {
            Bls12381 => Bls12381::get_order(),
            Bn254 => Bn254::get_order(),
            Ed25519 => Ed25519::get_order(),
        }
    }
}

#[repr(C)]
pub union GroupData {
    pub bls12381: ManuallyDrop<Bls12381>,
    pub bls12381g2: ManuallyDrop<Bls12381ECP2>,
    pub bls12381g3: ManuallyDrop<Bls12381FP12>,
    pub bn254: ManuallyDrop<Bn254>,
    pub bn254g2: ManuallyDrop<Bn254ECP2>,
    pub bn254g3: ManuallyDrop<Bn254FP12>,
    pub ed25519: ManuallyDrop<Ed25519>,
}

pub struct GroupElement {
    group: Group,
    data: GroupData,
    i:u8
}

impl PartialEq for GroupElement {
    fn eq(&self, other: &Self) -> bool {
        if self.group != other.group {
            return false;
        }
        unsafe {
            match self.group {
                Group::BLS12381 => (*self.data.bls12381).eq(&other.data.bls12381),
                Group::BN254 => (*self.data.bn254).eq(&other.data.bn254),
                Group::ED25519 => (*self.data.ed25519).eq(&other.data.ed25519),
                _ => todo!()
            }
        }
    }
}

impl Clone for GroupElement {
    fn clone(&self) -> Self {
        unsafe {
            match self.group {
                Group::BLS12381 => {
                    GroupElement { group:self.group.clone(), data: GroupData {bls12381:self.data.bls12381.clone()}, i:self.i }
                },
                Group::BN254 => {
                    GroupElement { group:self.group.clone(), data: GroupData {bn254:self.data.bn254.clone()}, i: self.i }
                },
                Group::ED25519 => {
                    GroupElement { group:self.group.clone(), data: GroupData {ed25519:self.data.ed25519.clone()}, i: self.i }
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
            Group::BLS12381 => data = GroupData {bls12381:ManuallyDrop::new(Bls12381::new())},
            Group::BN254 => data = GroupData {bn254:ManuallyDrop::new(Bn254::new())},
            Group::ED25519 => data = GroupData {ed25519:ManuallyDrop::new(Ed25519::new())},
            _ => todo!()
        }

        Self { group: group.clone(), data: data, i:0}
    }

        /*
    pub fn new_pair(group: &Group, i: u8) -> Self {
        let data;

        match group {
            Group::BLS12381 => {
                if i == 0 {
                data = GroupData {bls12381:ManuallyDrop::new(Bls12381::new())}
                }

        },
            Group::BN254 => data = GroupData {bn254:ManuallyDrop::new(Bn254::new())},
            Group::ED25519 => data = GroupData {ed25519:ManuallyDrop::new(Ed25519::new())},
            _ => todo!()
        }

        Self { group: group.clone(), data: data, i}
    }*/

    pub fn new_pow_big(group: &Group, y: &BigImpl) -> Self {
        let data;

        match group {
            Group::BLS12381 => data = GroupData {bls12381:ManuallyDrop::new(Bls12381::new_pow_big(y))},
            Group::BN254 => data = GroupData {bn254:ManuallyDrop::new(Bn254::new_pow_big(y))},
            Group::ED25519 => data = GroupData {ed25519:ManuallyDrop::new(Ed25519::new_pow_big(y))},
            _ => todo!()
        }

        Self { group: group.clone(), data: data, i:0}
    }

    pub fn init(group: &Group, data: GroupData) -> Self {
        Self {group:group.clone(), data, i:0}
    }

    pub fn new_rand(group: &Group, rng: &mut RNG) -> Self {
        let data;

        match group {
            Group::BLS12381 => data = GroupData {bls12381:ManuallyDrop::new(Bls12381::new_rand(rng))},
            Group::BN254 => data = GroupData {bn254:ManuallyDrop::new(Bn254::new_rand(rng))},
            Group::ED25519 => data = GroupData {ed25519:ManuallyDrop::new(Ed25519::new_rand(rng))},
            _ => todo!()
        }

        Self { group: group.clone(), data: data, i:0}
    }


    /// self = self*y
    pub fn mul(&mut self, y: &Self) {
        if self.group != y.group {
            panic!("incompatible groups!");
        }
        
        unsafe {
            match self.group {
                Group::BLS12381 => (*self.data.bls12381).mul(&(*y.data.bls12381)),
                Group::BN254 => (*self.data.bn254).mul(&(*y.data.bn254)),
                Group::ED25519 => (*self.data.ed25519).mul(&(*y.data.ed25519)),
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
                Group::BLS12381 => (*self.data.bls12381).div(&(*y.data.bls12381)),
                Group::BN254 => (*self.data.bn254).div(&(*y.data.bn254)),
                Group::ED25519 => (*self.data.ed25519).div(&(*y.data.ed25519)),
                _ => todo!()
            }
        }
    }

    ///self = self^y
    pub fn pow(&mut self, y: &BigImpl) {       
        unsafe {
            match self.group {
                Group::BLS12381 => (*self.data.bls12381).pow(&y),
                Group::BN254 => (*self.data.bn254).pow(&y),
                Group::ED25519 => (*self.data.ed25519).pow(&y),
                _ => todo!()
            }
        }
    }

    pub fn get_order(&self) -> BigImpl {
        match self.group {
            Group::BLS12381 => Bls12381::get_order(),
            Group::BN254 => Bn254::get_order(),
            Group::ED25519 => Ed25519::get_order(),
            _ => todo!()
        }
        
    }

    pub fn to_bytes(&self) -> Vec<u8> {       
        unsafe {
            match self.group {
                Group::BLS12381 => (*self.data.bls12381).to_bytes(),
                Group::BN254 => (*self.data.bn254).to_bytes(),
                Group::ED25519 => (*self.data.ed25519).to_bytes(),
                _ => todo!()
            }
        }
    }

    pub fn from_bytes(bytes: &[u8], group: &Group) -> Self {
        match group {
            Group::BLS12381 => Self { group:group.clone(), data:GroupData {bls12381:ManuallyDrop::new(Bls12381::from_bytes(bytes))}, i:0},
            Group::BN254 => Self { group:group.clone(), data:GroupData {bn254:ManuallyDrop::new(Bn254::from_bytes(bytes))}, i:0},
            Group::ED25519 => Self { group:group.clone(), data:GroupData {ed25519:ManuallyDrop::new(Ed25519::from_bytes(bytes))}, i:0},
            _ => todo!()
        }
    }
}