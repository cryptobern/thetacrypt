use mcore::rand::RAND;

use crate::bigint::*;
use crate::dl_schemes::common::*;
use crate::dl_schemes::ciphers::bz03::*;
use crate::dl_schemes::ciphers::sg02::*;

use super::DlDomain;
use super::dl_groups::BigImpl;
use super::dl_groups::dl_group::*;
use super::signatures::bls04::BLS04_PrivateKey;
use super::signatures::bls04::BLS04_PublicKey;

pub enum DlScheme<D: DlDomain> {
    BZ03(D),
    SG02(D),
    BLS04(D)
}

pub enum DlPrivateKey<D: DlDomain> {
    BZ03(BZ03_PrivateKey<D>),
    SG02(SG02_PrivateKey<D>),
    BLS04(BLS04_PrivateKey<D>)
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
    pub fn generate_keys<D: DlDomain>(k: usize, n: usize, rng: &mut impl RAND, scheme: &DlScheme<D>) -> Vec<DlPrivateKey<D>> {
        match scheme {
            DlScheme::BZ03(_D) => {
                if !D::is_pairing_friendly() {
                    panic!("Supplied domain does not support pairings!")
                }

                let x = D::BigInt::new_rand(&D::G2::get_order(), rng);
                let y = D::G2::new_pow_big(&x);

                let (shares, h): (Vec<BigImpl>, Vec<D>) = shamir_share(&x, k, n, rng);
                let mut privateKeys = Vec::new();
                let publicKey = BZ03_PublicKey::new(&y, &h );

                for i in 0..shares.len() {
                    privateKeys.push(DlPrivateKey::BZ03(BZ03_PrivateKey::new(i+1, &shares[i], &publicKey)))
                }

                return privateKeys;
            },

            DlScheme::SG02(_D) => {
                let x = D::BigInt::new_rand(&D::get_order(), rng);
                let y = D::new_pow_big(&x);

                let (shares, h): (Vec<BigImpl>, Vec<D>) = shamir_share(&x, k, n, rng);
                let mut privateKeys = Vec::new();

                let g_bar = D::new_rand(rng);

                let publicKey = SG02_PublicKey::new(&y,&h, &g_bar );

                for i in 0..shares.len() {
                    privateKeys.push(DlPrivateKey::SG02(SG02_PrivateKey::new(i+1, &shares[i], &publicKey)))
                }

                return privateKeys;
            },

            DlScheme::BLS04(_D) => {
                let x = D::BigInt::new_rand(&D::get_order(), rng);
                let y = D::new_pow_big(&x);

                let (shares, h): (Vec<BigImpl>, Vec<D>) = shamir_share(&x, k, n, rng);
                let mut privateKeys = Vec::new();

                let publicKey = BLS04_PublicKey::new(&y, &h);

                for i in 0..shares.len() {
                    privateKeys.push(DlPrivateKey::BLS04(BLS04_PrivateKey::new(i+1, &shares[i], &publicKey)))
                }

                return privateKeys;
            }

        }
    }
}

