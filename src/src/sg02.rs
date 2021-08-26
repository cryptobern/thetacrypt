#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use miracl_core::rand::RAND;
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::big;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::rom;
use miracl_core::bls12381::pair;
use miracl_core::hmac::*;
use miracl_core::aes::*;
use miracl_core::hash256::*;

pub struct SG02_PublicKey {
    y: ECP,
    verificationKey: Vec<ECP>,
    g_hat: ECP,
    group: ECGroup,
}

impl Clone for SG02_PublicKey {
    fn clone(&self) -> SG02_PublicKey {
        return SG02_PublicKey {y:self.y.clone(), verificationKey:self.verificationKey.clone(), g_hat:self.g_hat.clone(), group:ECGroup { q:self.group.q.clone(), g: ECP::generator() }};
    }
}

pub struct SG02_PrivateKey {
    id: u8,
    xi: BIG,
    pubkey: BZ03_PublicKey,
}

pub fn sg02_gen_keys(k: u8, n:u8, rng: &mut impl RAND) -> (BZ03_PublicKey, Vec<BZ03_PrivateKey>) {
    let x = BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng);
    let mut y = ECP2::generator();
    y = y.mul(&x);

    let s = BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng);
    let mut g_hat = ECP::generator();
    g_hat = g_hat.mul(&s);

    let (shares, h) = shamir_share(&x, &ECP::generator(), &k, &n, rng);
    let pk = BZ03_PublicKey {y:y.clone(), verificationKey:h.clone(), g_hat:g_hat, group:ECGroup { q:BIG::new_ints(&rom::CURVE_ORDER), g:ECP::generator() }};
    let mut sk: Vec<BZ03_PrivateKey> = Vec::new();
    
    for j in 1..n+1 {
        sk.push(BZ03_PrivateKey {id:j, xi:shares[(j -1) as usize], pubkey:pk.clone()});
    }

    (pk, sk)
}  