use mcore::rand::RAND;

use crate::interface::*;
use crate::bigint::*;
use crate::dl_schemes::common::*;
use crate::dl_schemes::bz03::*;
use crate::dl_schemes::sg02::*;

use super::DlDomain;
use super::dl_groups::BigImpl;
use super::dl_groups::bls12381::Bls12381;
use super::dl_groups::dl_group::*;
use super::dl_groups::pairing::*;

pub enum DlScheme<D: DlDomain> {
    BZ03(D),
    SG02(D)
}

pub enum DlPrivateKey<D: DlDomain> {
    BZ03(BZ03_PrivateKey<D>),
    SG02(SG02_PrivateKey<D>)
}

#[macro_export]
macro_rules! unwrap_keys {
    ($vec:expr, $variant:path) => {
        {
        let mut vec = Vec::new();
        for i in 0..$vec.len() {
            let val = &$vec[i];
            match val {
                $variant(x) => vec.push(x),
                _ => panic!("Error unwrapping key"),
            }
        }
        vec
        }
    };
}

pub struct DlKeyGenerator {}

impl DlKeyGenerator {
    pub fn generate_keys<D: DlDomain>(k: &u8, n: &u8, rng: &mut impl RAND, scheme: &DlScheme<D>) -> Vec<DlPrivateKey<D>> {
        match scheme {
            DlScheme::BZ03(D) => {
                if !D::is_pairing_friendly() {
                    panic!("Supplied domain does not support pairings but scheme relies on pairings!")
                }

                let x = D::BigInt::new_rand(&D::G2::get_order(), rng);
                let y = D::G2::new_pow_big(&x);

                let (shares, h): (Vec<BigImpl>, Vec<D>) = shamir_share(&x, &k, &n, rng);
                let mut privateKeys = Vec::new();
                let publicKey = BZ03_PublicKey { y: y, verificationKey:h };

                for i in 0..shares.len() {
                    privateKeys.push(DlPrivateKey::BZ03(BZ03_PrivateKey {xi: shares[i].clone(), pubkey: publicKey.clone(), id: (i+1) as u8} ))
                }

                return privateKeys;
            }

            ,
            DlScheme::SG02(D) => {
                let x = D::BigInt::new_rand(&D::get_order(), rng);
                let y = D::new_pow_big(&x);

                let (shares, h): (Vec<BigImpl>, Vec<D>) = shamir_share(&x, &k, &n, rng);
                let mut privateKeys = Vec::new();

                let g_bar = D::new_rand(rng);

                let publicKey = SG02_PublicKey { y: y, verificationKey:h, g_bar: g_bar };

                for i in 0..shares.len() {
                    privateKeys.push(DlPrivateKey::SG02(SG02_PrivateKey {xi: shares[i].clone(), pubkey: publicKey.clone(), id: (i+1) as u8} ))
                }

                return privateKeys;
            }

        }
    }
}

