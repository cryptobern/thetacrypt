use std::convert::TryInto;

use crate::dl_schemes::bigint::*;
use crate::dl_schemes::common::*;
use crate::dl_schemes::ciphers::bz03::*;
use crate::dl_schemes::ciphers::sg02::*;
use crate::rand::RNG;

use super::DlDomain;
use super::coins::cks05::Cks05PrivateKey;
use super::coins::cks05::Cks05PublicKey;
use super::dl_groups::dl_group::*;
use super::signatures::bls04::Bls04PrivateKey;
use super::signatures::bls04::Bls04PublicKey;

pub enum DlScheme<D: DlDomain> {
    BZ03(D),
    SG02(D),
    BLS04(D),
    CKS05(D)
}

pub enum DlPrivateKey<D: DlDomain> {
    BZ03(Bz03PrivateKey<D>),
    SG02(Sg02PrivateKey<D>),
    BLS04(Bls04PrivateKey<D>),
    CKS05(Cks05PrivateKey<D>)
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
            }
        }
    }
}

