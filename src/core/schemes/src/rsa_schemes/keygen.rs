use std::time::Instant;
use crate::rand::RNG;
use crate::{rsa_schemes::{common::{gen_strong_prime, fac}, bigint::RsaBigInt}, BIGINT, ONE};

use super::{common::shamir_share, signatures::sh00::{Sh00PrivateKey, Sh00PublicKey, Sh00VerificationKey}};

const DEBUG:bool = false;

pub enum RsaScheme {
    Sh00(usize)
}

pub enum RsaPrivateKey {
    Sh00(Sh00PrivateKey)
}

pub struct RsaKeyGenerator {}

impl RsaKeyGenerator {
    pub fn generate_keys(k: usize, n: usize, rng: &mut RNG, scheme: RsaScheme) -> Vec<RsaPrivateKey> {
        match scheme {
            RsaScheme::Sh00(MODSIZE) => {
                let PLEN = MODSIZE/2 - 2; 

                let mut p1 = RsaBigInt::new_rand(rng, PLEN);
                let mut q1 = RsaBigInt::new_rand(rng, PLEN);

                let mut p: RsaBigInt = RsaBigInt::new();
                let mut q: RsaBigInt = RsaBigInt::new();

                let e = BIGINT!(65537); // Question: Should we be able to change this?

                if DEBUG { debug!("generating strong primes..."); }

                let now = Instant::now();
                gen_strong_prime(&mut p1, &mut p, &e, rng, PLEN);
                let elapsed_time = now.elapsed().as_millis();
                if DEBUG { debug!("found first prime p in {}ms: {}", elapsed_time, p.to_string()); }
                
                let now = Instant::now();
                gen_strong_prime(&mut q1, &mut q, &e,  rng, PLEN);
                let elapsed_time = now.elapsed().as_millis();
                if DEBUG { debug!("found second prime q in {}ms: {}", elapsed_time, q.to_string()); }
                
                let N = p.mul(&q);
                let m = p1.mul(&q1);

                let v = RsaBigInt::new_rand(rng, MODSIZE - 1).pow(2).rmod(&N);

                let d = e.inv_mod(&m);

                let delta = fac(n);
                let (xi, vi) = shamir_share(&d, k, n, &N, &m, &v, MODSIZE, rng);
                
                let mut u;
                let mut up;
                let mut uq;
                loop {
                    u = RsaBigInt::new_rand(rng, MODSIZE - 1);
                    up = u.pow_mod(&p1, &p);
                    uq = u.pow_mod(&q1, &q);
                    if up.equals(&ONE!()) != uq.equals(&ONE!())  {
                        break;
                    }
                }

                let verificationKey = Sh00VerificationKey::new(v, vi, u);
                let pubkey = Sh00PublicKey::new(k as u32, N,  e.clone(), verificationKey, delta, MODSIZE);
                
                let mut pks: Vec<RsaPrivateKey> = Vec::new();
                for i in 0..n {
                    pks.push(RsaPrivateKey::Sh00(
                            Sh00PrivateKey::new(xi[i].0, m.clone(), xi[i].1.clone(), pubkey.clone())))
                }
                pks
            }
        }
    }
}
