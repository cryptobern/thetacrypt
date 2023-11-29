use crate::interface::ThresholdCryptoError;
use crate::{
    dl_schemes::{
        bigint::BigImpl,
        dl_groups::{bls12381::Bls12381, bn254::Bn254, ed25519::Ed25519},
    },
    group::GroupElement,
    group_generators,
};
use theta_proto::scheme_types::{Group, ThresholdScheme};

pub trait SchemeDetails {
    fn get_id(&self) -> u8;
    fn from_id(id: u8) -> Option<ThresholdScheme>;
    fn parse_string(scheme: &str) -> Result<ThresholdScheme, ThresholdCryptoError>;
    fn is_interactive(&self) -> bool;
    fn check_valid_group(&self, group: Group) -> bool;
}

impl SchemeDetails for ThresholdScheme {
    fn get_id(&self) -> u8 {
        *self as u8
    }

    fn from_id(id: u8) -> Option<Self> {
        ThresholdScheme::from_i32(id as i32)
    }

    fn parse_string(scheme: &str) -> Result<Self, ThresholdCryptoError> {
        match scheme {
            "Bz03" => Ok(Self::Bz03),
            "Sg02" => Ok(Self::Sg02),
            "Bls04" => Ok(Self::Bls04),
            "Cks05" => Ok(Self::Cks05),
            "Frost" => Ok(Self::Frost),
            "Sh00" => Ok(Self::Sh00),
            _ => Err(ThresholdCryptoError::UnknownScheme),
        }
    }

    fn is_interactive(&self) -> bool {
        match self {
            Self::Frost => true,
            _ => false,
        }
    }

    fn check_valid_group(&self, group: Group) -> bool {
        match self {
            Self::Bls04 => group.is_dl() && group.supports_pairings(),
            Self::Bz03 => group.is_dl() && group.supports_pairings(),
            Self::Cks05 => group.is_dl(),
            Self::Frost => group.is_dl(),
            Self::Sg02 => group.is_dl(),
            Self::Sh00 => !group.is_dl(),
        }
    }
}

pub trait GroupDetails {
    fn is_dl(&self) -> bool;
    fn get_code(&self) -> u8;
    fn from_code(code: u8) -> Result<Group, ThresholdCryptoError>;
    fn parse_string(name: &str) -> Result<Group, ThresholdCryptoError>;
    fn get_order(&self) -> BigImpl;
    fn supports_pairings(&self) -> bool;
    fn get_alternate_generator(&self) -> GroupElement;
}

impl GroupDetails for Group {
    /* returns whether the group is a discrete logarithm group */
    fn is_dl(&self) -> bool {
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
    fn get_code(&self) -> u8 {
        match self {
            Self::Bls12381 => 0,
            Self::Bn254 => 1,
            Self::Ed25519 => 2,
            Self::Rsa512 => 3,
            Self::Rsa1024 => 4,
            Self::Rsa2048 => 5,
            Self::Rsa4096 => 6,
        }
    }

    fn from_code(code: u8) -> Result<Self, ThresholdCryptoError> {
        match code {
            0 => Ok(Self::Bls12381),
            1 => Ok(Self::Bn254),
            2 => Ok(Self::Ed25519),
            3 => Ok(Self::Rsa512),
            4 => Ok(Self::Rsa1024),
            5 => Ok(Self::Rsa2048),
            6 => Ok(Self::Rsa4096),
            _ => Err(ThresholdCryptoError::UnknownGroup),
        }
    }

    fn parse_string(name: &str) -> Result<Self, ThresholdCryptoError> {
        match name {
            "bls12381" => Ok(Self::Bls12381),
            "bn254" => Ok(Self::Bn254),
            "ed25519" => Ok(Self::Ed25519),
            "rsa512" => Ok(Self::Rsa512),
            "rsa1024" => Ok(Self::Rsa1024),
            "rsa2048" => Ok(Self::Rsa2048),
            "rsa4096" => Ok(Self::Rsa4096),
            _ => Err(ThresholdCryptoError::UnknownGroupString),
        }
    }

    /* returns the group order */
    fn get_order(&self) -> BigImpl {
        match self {
            Self::Bls12381 => Bls12381::get_order(),
            Self::Bn254 => Bn254::get_order(),
            Self::Ed25519 => Ed25519::get_order(),
            _ => panic!("not applicable"),
        }
    }

    /* returns whether the group supports pairings */
    fn supports_pairings(&self) -> bool {
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
    // for this cyclic group.
    fn get_alternate_generator(&self) -> GroupElement {
        match self {
            Self::Bls12381 => GroupElement::from_bytes(
                &group_generators::BLS12381_ALTERNATE_GENERATOR_BYTES,
                &self,
                None,
            ),
            Self::Bn254 => GroupElement::from_bytes(
                &group_generators::BN254_ALTERNATE_GENERATOR_BYTES,
                &self,
                None,
            ),
            _ => panic!("no alternate generator available"),
        }
    }
}
