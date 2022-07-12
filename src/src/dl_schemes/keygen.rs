use std::convert::TryInto;

use rasn::AsnType;
use rasn::Decode;
use rasn::Encode;
use rasn::Encoder;
use rasn::der::decode;

use crate::dl_schemes::bigint::*;
use crate::dl_schemes::common::*;
use crate::dl_schemes::ciphers::bz03::*;
use crate::dl_schemes::ciphers::sg02::*;
use crate::dl_schemes::dl_groups::bls12381::Bls12381;
use crate::interface::Serializable;
use crate::rand::RNG;
use crate::rand::RngAlgorithm;

use super::DlDomain;
use super::coins::cks05::Cks05PrivateKey;
use super::coins::cks05::Cks05PublicKey;
use super::dl_groups::dl_group::*;
use super::signatures::bls04::Bls04PrivateKey;
use super::signatures::bls04::Bls04PublicKey;
use super::signatures::frost::FrostPrivateKey;
use super::signatures::frost::FrostPublicKey;
use super::signatures::frost::FrostSignatureShare;

pub enum DlScheme<D: DlDomain> {
    BZ03(D),
    SG02(D),
    BLS04(D),
    CKS05(D),
    FROST(D)
}

#[derive(AsnType, Clone, PartialEq)]
#[rasn(enumerated)]
pub enum DlPrivateKey<D: DlDomain> {
    BZ03(Bz03PrivateKey<D>),
    SG02(Sg02PrivateKey<D>),
    BLS04(Bls04PrivateKey<D>),
    CKS05(Cks05PrivateKey<D>),
    FROST(FrostPrivateKey<D>)
}

impl<D: DlDomain> Decode for DlPrivateKey<D> {
    fn decode_with_tag<Dec: rasn::Decoder>(decoder: &mut Dec, tag: rasn::Tag) -> Result<Self, Dec::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let keyType = u8::decode(sequence)?;
            let bytes = Vec::<u8>::decode(sequence)?;

            match keyType {
                0 => {
                    let key: Bz03PrivateKey<D> = decode(&bytes).unwrap();
                    Ok(DlPrivateKey::BZ03(key))
                },
                1 => {
                    let key: Sg02PrivateKey<D> = decode(&bytes).unwrap();
                    Ok(DlPrivateKey::SG02(key))
                }, 
                2 => {
                    let key: Bls04PrivateKey<D> = decode(&bytes).unwrap();
                    Ok(DlPrivateKey::BLS04(key))
                }, 
                3 => {
                    let key: Cks05PrivateKey<D> = decode(&bytes).unwrap();
                    Ok(DlPrivateKey::CKS05(key))
                },
                4 => {
                    let key: FrostPrivateKey<D> = decode(&bytes).unwrap();
                    Ok(DlPrivateKey::FROST(key))
                },
                _ => {
                    panic!("unknown key encoding!");
                }
            }
        })
    }
}

impl<D: DlDomain> Encode for DlPrivateKey<D> {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        
        match self  {
            Self::BZ03(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (0 as u8).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::SG02(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (1 as u8).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::BLS04(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (2 as u8).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::CKS05(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (3 as u8).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::FROST(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (4 as u8).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            }
        }
    }
}

#[macro_export]
macro_rules! unwrap_keys {
    ($vec:expr, $variant:path) => {
        {
        let mut vec = Vec::new();
        for i in 0..$vec.len() {
            let val = &$vec[i];
            match val {
                $variant(x) => {
                    vec.push((*x).clone())
                },
                _ => panic!("Error unwrapping key"),
            }
        }
        vec
        }
    };
}

pub struct DlKeyGenerator {}

impl DlKeyGenerator {
    pub fn generate_keys<D: DlDomain>(k: usize, n: usize, rng: &mut RNG, scheme: &DlScheme<D>) -> Vec<DlPrivateKey<D>> {
        match scheme {
            DlScheme::BZ03(_D) => {
                if !D::is_pairing_friendly() {
                    panic!("Supplied domain does not support pairings!")
                }

                let x = D::BigInt::new_rand(&D::G2::get_order(), rng);
                let y = D::G2::new_pow_big(&x);

                let (shares, h): (Vec<BigImpl>, Vec<D>) = shamir_share(&x, k, n, rng);
                let mut privateKeys = Vec::new();
                let publicKey = Bz03PublicKey::new(k as u32, &y, &h );

                for i in 0..shares.len() {
                    privateKeys.push(DlPrivateKey::BZ03(Bz03PrivateKey::new((i+1) as u32, &shares[i], &publicKey)))
                }

                return privateKeys;
            },

            DlScheme::SG02(_D) => {
                let x = D::BigInt::new_rand(&D::get_order(), rng);
                let y = D::new_pow_big(&x);

                let (shares, h): (Vec<BigImpl>, Vec<D>) = shamir_share(&x, k, n, rng);
                let mut privateKeys = Vec::new();

                let g_bar = D::new_rand(rng);

                let publicKey = Sg02PublicKey::new(k as u32, &y,&h, &g_bar );

                for i in 0..shares.len() {
                    privateKeys.push(DlPrivateKey::SG02(Sg02PrivateKey::new((i+1).try_into().unwrap(), &shares[i], &publicKey)))
                }

                return privateKeys;
            },

            DlScheme::BLS04(_D) => {
                let x = D::BigInt::new_rand(&D::get_order(), rng);
                let y = D::new_pow_big(&x);

                let (shares, h): (Vec<BigImpl>, Vec<D>) = shamir_share(&x, k, n, rng);
                let mut privateKeys = Vec::new();

                let publicKey = Bls04PublicKey::new(k as u32, &y, &h);

                for i in 0..shares.len() {
                    privateKeys.push(DlPrivateKey::BLS04(Bls04PrivateKey::new((i+1).try_into().unwrap(), &shares[i], &publicKey)))
                }

                return privateKeys;
            },

            DlScheme::CKS05(_D) => {
                let x = D::BigInt::new_rand(&D::get_order(), rng);
                let y = D::new_pow_big(&x);

                let (shares, h): (Vec<BigImpl>, Vec<D>) = shamir_share(&x, k, n, rng);
                let mut privateKeys = Vec::new();

                let publicKey = Cks05PublicKey::new(k as u32, &y,&h);

                for i in 0..shares.len() {
                    privateKeys.push(DlPrivateKey::CKS05(Cks05PrivateKey::new((i+1) as u32, &shares[i], &publicKey)))
                }

                return privateKeys;
            },

            DlScheme::FROST(_D) => {
                let x = D::BigInt::new_rand(&D::get_order(), rng);
                let y = D::new_pow_big(&x);

                let (shares, h): (Vec<BigImpl>, Vec<D>) = shamir_share(&x, k, n, rng);
                let mut privateKeys = Vec::new();

                let publicKey = FrostPublicKey::new(k as u32, &y, &h);

                for i in 0..shares.len() {
                    privateKeys.push(DlPrivateKey::FROST(FrostPrivateKey::new((i+1).try_into().unwrap(), &shares[i], &publicKey)))
                }

                return privateKeys;
            }
        }
    }
}