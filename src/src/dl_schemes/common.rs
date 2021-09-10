use mcore::{hmac::{MC_SHA2, hkdf_expand, hkdf_extract}, rand::RAND};

use crate::dl_schemes::dl_groups::dl_group::*;
use crate::bigint::*;

use super::{DlShare, dl_groups::BigImpl};

pub fn shamir_share<G: DlGroup>(x: &BigImpl, k: usize, n: usize, rng: &mut impl RAND) -> (Vec<BigImpl>, Vec<G>) {
    let mut coeff: Vec<BigImpl> = Vec::new();
    let q = G::get_order();

    for _ in 0..k-1 {
        coeff.push(G::BigInt::new_rand(&q, rng));
    }

    coeff.push(G::BigInt::new_copy(x));
    let mut shares: Vec<BigImpl> = Vec::new();
    let mut h: Vec<G> = Vec::new();

    for j in 1..n+1 {
        let xi = eval_pol::<G>(&G::BigInt::new_int(j as isize), &mut coeff);
        let mut hi = G::new();
        hi.pow(&xi);
        h.push(hi);
        
        shares.push(xi);
    }

    (shares, h)
}

pub fn eval_pol<G: DlGroup>(x: &BigImpl, a: &Vec<BigImpl>) ->  BigImpl {
    let len = (a.len()) as isize;
    let mut val = G::BigInt::new_int(0);
    let q = G::get_order();
    
    for i in 0..len - 1 {
        let mut tmp = G::BigInt::new_copy(&a[i as usize].clone());
        let mut xi = x.clone();

        xi.pow_mod(&G::BigInt::new_int(len - i - 1), &q);
        tmp.mul_mod(&xi, &G::get_order());
        val.add(&tmp);
    }

    val.add(&a[(len - 1) as usize]);
    val.rmod(&q);

    val
}


pub fn xor(v1: Vec<u8>, v2: Vec<u8>) -> Vec<u8> {
    let v3: Vec<u8> = v1
    .iter()
    .zip(v2.iter())
    .map(|(&x1, &x2)| x1 ^ x2)
    .collect();

    v3
}

pub fn gen_symm_key(rng: &mut impl RAND) -> [u8; 32] {
    let prk: &mut [u8] = &mut[0;32];
    let mut ikm: Vec<u8> = Vec::new();
    for _ in 0..32 {
        ikm.push(rng.getbyte());
    }

    let salt: Vec<u8> = Vec::new();
    hkdf_extract(MC_SHA2, 32, prk, Option::Some(&salt), &ikm);

    let k: &mut[u8;32] = &mut[0;32];
    hkdf_expand(MC_SHA2, 32, k, 16, prk, &[0]);
    
    *k
}

pub fn interpolate<G: DlGroup, S: DlShare<G>>(shares: &Vec<S>) -> G { 
    let ids:Vec<u8> = (0..shares.len()).map(|x| shares[x].get_id() as u8).collect();
    let mut rY = G::new();

    for i in 0..shares.len() {
        let l = lagrange_coeff::<G>(&ids, shares[i].get_id() as isize);
        let mut ui = shares[i].get_data().clone();
        ui.pow(&l);

        if i == 0 {
            rY = ui;
        } else {
            rY.mul(&ui);
        }
    }

    rY
}

pub fn lagrange_coeff<G: DlGroup>(indices: &[u8], i: isize) -> BigImpl {
    let mut prod = G::BigInt::new_int(1);
    let q = G::get_order();
    
    for k in 0..indices.len() {
        let j:isize = indices[k].into();

        if i != j {
            let mut ij;
            let val = (j - i).abs();

            if i > j {
                ij = G::get_order();
                ij.sub(&G::BigInt::new_int(val));
            } else {
                ij = G::BigInt::new_int(val);
            }
            ij.inv_mod(&q);
            ij.imul(j as isize);

            prod.rmod(&q);
            prod.mul_mod(&ij, &q);
        }
    } 
    
    prod.rmod(&q);
    prod
}