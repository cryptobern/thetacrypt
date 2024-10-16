use std::time::Instant;

use log::debug;
use theta_proto::scheme_types::{Group, ThresholdScheme};

use crate::{
    dl_schemes::{
        ciphers::{
            bz03::{Bz03PrivateKey, Bz03PublicKey},
            sg02::{Sg02PrivateKey, Sg02PublicKey},
        },
        coins::cks05::{Cks05PrivateKey, Cks05PublicKey},
        common::shamir_share,
        signatures::{
            bls04::{Bls04PrivateKey, Bls04PublicKey},
            frost::{FrostPrivateKey, FrostPublicKey},
        },
    },
    groups::group::{GroupElement, GroupOperations},
    integers::{bigint::BigInt, sizedint::SizedBigInt},
    interface::SchemeError,
    rand::RNG,
    rsa_schemes::{
        common::{fac, gen_strong_prime, shamir_share_rsa},
        signatures::sh00::{Sh00PrivateKey, Sh00PublicKey, Sh00VerificationKey},
    },
    scheme_types_impl::GroupDetails,
    BIGINT, DEBUG, ONE,
};

use super::keys::PrivateKeyShare;

pub struct KeyParams {
    e: BigInt,
}

impl KeyParams {
    pub fn new() -> Self {
        return Self { e: BIGINT!(65537) };
    }

    pub fn set_e(&mut self, e: &BigInt) {
        self.e.set(e);
    }
}

pub struct KeyGenerator {}
#[allow(non_snake_case)]
impl KeyGenerator {
    pub fn generate_keys(
        k: usize,
        n: usize,
        rng: &mut RNG,
        scheme: &ThresholdScheme,
        group: &Group,
        params: &Option<KeyParams>,
    ) -> Result<Vec<PrivateKeyShare>, SchemeError> {
        if k > n || n < 1 {
            return Err(SchemeError::InvalidParams(None));
        }

        match scheme {
            ThresholdScheme::Bz03 => {
                if !group.supports_pairings() {
                    return Err(SchemeError::CurveDoesNotSupportPairings);
                }

                if !group.is_dl() {
                    return Err(SchemeError::IncompatibleGroup);
                }

                let x = SizedBigInt::new_rand(&group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big_ecp2(&group, &x);

                let (shares, h) = shamir_share(&x, k, n, rng);
                let mut private_keys = Vec::new();
                let public_key = Bz03PublicKey::new(&group, n, k, &y, &h);

                for i in 0..shares.len() {
                    private_keys.push(PrivateKeyShare::Bz03(Bz03PrivateKey::new(
                        (i + 1) as u16,
                        &shares[i],
                        &public_key,
                    )))
                }

                return Result::Ok(private_keys);
            }

            ThresholdScheme::Sg02 => {
                if !group.is_dl() {
                    return Err(SchemeError::IncompatibleGroup);
                }

                let x = SizedBigInt::new_rand(group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big(&group, &x);

                let (shares, h): (Vec<SizedBigInt>, Vec<GroupElement>) =
                    shamir_share(&x, k as usize, n as usize, rng);
                let mut private_keys = Vec::new();

                let g_bar = GroupElement::new_rand(group, rng);

                let public_key = Sg02PublicKey::new(n, k, group, &y, &h, &g_bar);

                for i in 0..shares.len() {
                    private_keys.push(PrivateKeyShare::Sg02(Sg02PrivateKey::new(
                        (i + 1).try_into().unwrap(),
                        &shares[i],
                        &public_key,
                    )))
                }

                return Result::Ok(private_keys);
            }

            ThresholdScheme::Bls04 => {
                if !group.supports_pairings() {
                    return Err(SchemeError::CurveDoesNotSupportPairings);
                }

                if !group.is_dl() {
                    return Err(SchemeError::IncompatibleGroup);
                }

                let x = SizedBigInt::new_rand(&group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big(&group, &x);

                let (shares, h) = shamir_share(&x, k, n, rng);
                let mut private_keys = Vec::new();
                let public_key = Bls04PublicKey::new(&group, n, k, &y, &h);

                for i in 0..shares.len() {
                    private_keys.push(PrivateKeyShare::Bls04(Bls04PrivateKey::new(
                        (i + 1) as u16,
                        &shares[i],
                        &public_key,
                    )))
                }

                return Result::Ok(private_keys);
            }

            ThresholdScheme::Cks05 => {
                if !group.is_dl() {
                    return Err(SchemeError::IncompatibleGroup);
                }

                let x = SizedBigInt::new_rand(&group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big(&group, &x);

                let (shares, h): (Vec<SizedBigInt>, Vec<GroupElement>) =
                    shamir_share(&x, k as usize, n as usize, rng);
                let mut private_keys = Vec::new();

                let public_key = Cks05PublicKey::new(group, n, k, &y, &h);

                for i in 0..shares.len() {
                    private_keys.push(PrivateKeyShare::Cks05(Cks05PrivateKey::new(
                        (i + 1) as u16,
                        &shares[i],
                        &public_key,
                    )));
                }

                return Ok(private_keys);
            }

            ThresholdScheme::Frost => {
                let x = SizedBigInt::new_rand(group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big(&group, &x);

                let (shares, h): (Vec<SizedBigInt>, Vec<GroupElement>) =
                    shamir_share(&x, k as usize, n as usize, rng);
                let mut private_keys = Vec::new();

                let public_key = FrostPublicKey::new(n, k, group, &y, &h);

                for i in 0..shares.len() {
                    private_keys.push(PrivateKeyShare::Frost(FrostPrivateKey::new(
                        (i + 1).try_into().unwrap(),
                        &shares[i],
                        &public_key,
                    )));
                }

                return Result::Ok(private_keys);
            }

            ThresholdScheme::Sh00 => {
                if group.is_dl() {
                    return Err(SchemeError::IncompatibleGroup);
                }

                let mut e = BIGINT!(65537);

                if params.is_some() {
                    e.set(&params.as_ref().unwrap().e);
                }

                let modsize: usize;
                match group {
                    Group::Rsa512 => modsize = 512,
                    Group::Rsa1024 => modsize = 1024,
                    Group::Rsa2048 => modsize = 2048,
                    &Group::Rsa4096 => modsize = 4096,
                    _ => return Err(SchemeError::WrongGroup),
                }

                let plen = modsize / 2 - 2;

                let mut p1 = BigInt::new_rand(rng, plen);
                let mut q1 = BigInt::new_rand(rng, plen);

                let mut p = BigInt::new();
                let mut q = BigInt::new();

                if DEBUG {
                    debug!("generating strong primes...");
                }

                let now = Instant::now();
                gen_strong_prime(&mut p1, &mut p, &e, rng, plen);
                let elapsed_time = now.elapsed().as_millis();
                if DEBUG {
                    debug!(
                        "found first prime p in {}ms: {}",
                        elapsed_time,
                        p.to_string()
                    );
                }

                let now = Instant::now();
                gen_strong_prime(&mut q1, &mut q, &e, rng, plen);
                let elapsed_time = now.elapsed().as_millis();
                if DEBUG {
                    debug!(
                        "found second prime q in {}ms: {}",
                        elapsed_time,
                        q.to_string()
                    );
                }

                let N = p.mul(&q);
                let m = p1.mul(&q1);

                let v = BigInt::new_rand(rng, modsize - 1).pow(2).rmod(&N);

                let d = e.inv_mod(&m);

                let delta = fac(BIGINT!(n));
                let (xi, vi) = shamir_share_rsa(&d, k, n, &N, &m, &v, modsize, rng);

                let mut u;
                let mut up;
                let mut uq;
                loop {
                    u = BigInt::new_rand(rng, modsize - 1);
                    up = u.pow_mod(&p1, &p);
                    uq = u.pow_mod(&q1, &q);
                    if up.equals(&ONE!()) != uq.equals(&ONE!()) {
                        break;
                    }
                }

                let verification_key = Sh00VerificationKey::new(v, vi, u);
                let pubkey = Sh00PublicKey::new(
                    n as u16,
                    k as u16,
                    N,
                    e.clone(),
                    verification_key,
                    delta,
                    modsize,
                );

                let mut pks: Vec<PrivateKeyShare> = Vec::new();
                for i in 0..n {
                    pks.push(PrivateKeyShare::Sh00(Sh00PrivateKey::new(
                        xi[i].0, &m, &xi[i].1, &pubkey,
                    )))
                }
                Ok(pks)
            }
        }
    }
}
