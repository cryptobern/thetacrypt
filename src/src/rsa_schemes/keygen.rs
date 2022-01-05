use std::time::Instant;
use mcore::rand::RAND;

use crate::rsa_schemes::{common::{bytes2int, gen_strong_prime, fac}, rsa_mod::RsaModulus, bigint::BigInt};

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

                let e: BigInt = BigInt::new_prime(rng, ESIZE/8);
                println!("e: {}", e.to_string());   

                println!("generating strong primes...");

                let now = Instant::now();
                gen_strong_prime(&mut p1, &mut p, &e, rng, PLEN/8);
                let elapsed_time = now.elapsed();
                println!("found first prime p in {} seconds: {}", elapsed_time.as_secs(), p.to_string());
                
                let now = Instant::now();
                gen_strong_prime(&mut q1, &mut q, &e,  rng, PLEN/8);
                let elapsed_time = now.elapsed();
                println!("found second prime q in {} seconds: {}", elapsed_time.as_secs(), q.to_string());
                
                let modulus = RsaModulus::new(&p1, &q1);

                let d = modulus.inv_m(&e.clone());

                let (xi, v, vi) = shamir_share(&d, k, n, &modulus.get_m(), rng);
                
                let u = BigInt::new();

                let verificationKey = SH00_VerificationKey::new(v, vi, u);
                let pubkey = SH00_PublicKey::new(modulus.get_n(), e.clone(), verificationKey, n );
                
                let mut pks: Vec<RsaPrivateKey> = Vec::new();
                for i in 0..n {
                    pks.push(RsaPrivateKey::SH00(
                            SH00_PrivateKey::new(i, modulus.clone(), xi[i].clone(), pubkey.clone())))
                }
                pks
            }
        }
    }
}
