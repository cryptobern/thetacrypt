use mcore::{hmac::{MC_SHA2, hkdf_expand, hkdf_extract}, rand::RAND};

use crate::{dl_schemes::dl_groups::dl_group::*, rand::RNG, interface::DecryptionShare};
use crate::dl_schemes::bigint::*;

pub trait DlShare {
    fn get_id(&self) -> u32;
    fn get_data(&self) -> GroupElement;
    fn get_group(&self) -> Group;
}

pub fn shamir_share(x: &BigImpl, k: usize, n: usize, rng: &mut RNG) -> (Vec<BigImpl>, Vec<GroupElement>) {
    let mut coeff: Vec<BigImpl> = Vec::new();
    let group = x.get_group();
    let q = group.get_order();

    for _ in 0..k-1 {
        coeff.push(BigImpl::new_rand(&group, &q, rng));
    }

    coeff.push(BigImpl::new_copy(x));
    let mut shares: Vec<BigImpl> = Vec::new();
    let mut h: Vec<GroupElement> = Vec::new();

    for j in 1..n+1 {
        let xi = eval_pol(&BigImpl::new_int(&group, j as isize), &mut coeff);
        let mut hi = GroupElement::new(&group);
        hi.pow(&xi);
        h.push(hi);
        
        shares.push(xi);
    }

    (shares, h)
}

pub fn eval_pol(x: &BigImpl, a: &Vec<BigImpl>) ->  BigImpl {
    let len = (a.len()) as isize;
    let group = x.get_group();
    let mut val = BigImpl::new_int(&group, 0);
    let q = group.get_order();
    
    for i in 0..len - 1 {
        let mut tmp = BigImpl::new_copy(&a[i as usize].clone());
        let mut xi = x.clone();

        xi.pow_mod(&BigImpl::new_int(&group, len - i - 1), &q);
        tmp.mul_mod(&xi, &group.get_order());
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

pub fn gen_symm_key(rng: &mut RNG) -> [u8; 32] {
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

pub fn interpolate<T: DlShare>(shares: &Vec<T>) -> GroupElement { 
    let ids:Vec<u8> = (0..shares.len()).map(|x| shares[x].get_id() as u8).collect();
    let mut rY = GroupElement::new(&shares[0].get_group());

    for i in 0..shares.len() {
        let l = lagrange_coeff(&shares[0].get_group(), &ids, shares[i].get_id() as isize);
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

pub fn lagrange_coeff(group: &Group, indices: &[u8], i: isize) -> BigImpl {
    let mut prod = BigImpl::new_int(group, 1);
    let q = group.get_order();
    
    for k in 0..indices.len() {
        let j:isize = indices[k].into();

        if i != j {
            let mut ij;
            let val = (j - i).abs();

            if i > j {
                ij = q.clone();
                ij.sub(&BigImpl::new_int(group, val));
            } else {
                ij = BigImpl::new_int(group, val);
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