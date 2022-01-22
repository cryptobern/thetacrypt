use std::time::Instant;
use mcore::rand::RAND;

use crate::{rsa_schemes::{common::{bytes2int, gen_strong_prime, fac}, rsa_mod::RsaModulus, bigint::BigInt}, BIGINT};

use super::{common::shamir_share, rsa_groups::{rsa_domain::RsaDomain, rsa_domain::BigFiniteField }, signatures::sh00::{SH00_PrivateKey, SH00_PublicKey, SH00_VerificationKey}};

pub enum RsaScheme {
    SH00(usize)
}

pub enum RsaPrivateKey {
    SH00(SH00_PrivateKey)
}

pub struct RsaKeyGenerator {}

impl RsaKeyGenerator {
    pub fn generate_keys(k: usize, n: usize, rng: &mut impl RAND, scheme: RsaScheme) -> Vec<RsaPrivateKey> {
        match scheme {
            RsaScheme::SH00(PLEN) => {
                const ESIZE:usize = 32;

                let mut p1 = BigInt::new_rand(rng, PLEN/8);
                let mut q1 = BigInt::new_rand(rng, PLEN/8);

                let mut p: BigInt = BigInt::new();
                let mut q: BigInt = BigInt::new();

                //let e: BigInt = BigInt::new_prime(rng, ESIZE/8);
                let e = BIGINT!(65537); // Question: Should we be able to change this?

                println!("generating strong primes...");

                let now = Instant::now();
                gen_strong_prime(&mut p1, &mut p, &e, rng, PLEN/8);
                let elapsed_time = now.elapsed().as_millis();
                println!("found first prime p in {}ms: {}", elapsed_time, p.to_string());
                
                let now = Instant::now();
                gen_strong_prime(&mut q1, &mut q, &e,  rng, PLEN/8);
                let elapsed_time = now.elapsed().as_millis();
                println!("found second prime q in {}ms: {}", elapsed_time, q.to_string());
                
                let modulus = RsaModulus::new(&p1, &q1, PLEN);

                let d = modulus.inv_m(&e.clone());

                let mut v;

                loop {
                    v = BigInt::new_rand(rng, PLEN/8 - 1); // TODO: change this -> should be random in {0, ..., n-1}
                    if v.legendre(&modulus.get_n()) == 1 {
                        break
                    }
                }

                let delta = fac(n);
                let (xi, vi) = shamir_share(&d, k, n, &modulus.get_m(), &v, rng);
                
                let mut u;

                loop {
                    u = BigInt::new_rand(rng, PLEN/8 - 1);
                    if BigInt::jacobi(&u, &modulus.get_n()) == -1 {
                        break;
                    }
                }

                let verificationKey = SH00_VerificationKey::new(v, vi, u);
                let pubkey = SH00_PublicKey::new(modulus.get_n(),  e.clone(), verificationKey, delta, PLEN);
                
                let mut pks: Vec<RsaPrivateKey> = Vec::new();
                for i in 0..n {
                    pks.push(RsaPrivateKey::SH00(
                            SH00_PrivateKey::new(xi[i].0, modulus.clone(), xi[i].1.clone(), pubkey.clone())))
                }
                pks
            }
        }
    }
}
