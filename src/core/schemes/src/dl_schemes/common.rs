use mcore::{
    hmac::{hkdf_expand, hkdf_extract, MC_SHA2},
    rand::RAND,
};

use crate::{
    groups::ec::*,
    interface::{DecryptionShare, DlShare},
    rand::RNG,
    scheme_types_impl::GroupDetails,
};

use crate::groups::group::GroupOperations;
use crate::integers::sizedint::SizedBigInt;
use theta_proto::scheme_types::Group;

use crate::groups::group::GroupElement;

/*
    share secret x using shamir secret sharing with n parties and a threshold of k
*/
pub fn shamir_share(
    x: &SizedBigInt,
    k: usize,
    n: usize,
    rng: &mut RNG,
) -> (Vec<SizedBigInt>, Vec<GroupElement>) {
    let mut coeff: Vec<SizedBigInt> = Vec::new();
    let group = x.get_group();
    let q = group.get_order();

    for _ in 0..k - 1 {
        coeff.push(SizedBigInt::new_rand(&group, &q, rng));
    }

    coeff.push(SizedBigInt::new_copy(x));
    let mut shares: Vec<SizedBigInt> = Vec::new();
    let mut h: Vec<GroupElement> = Vec::new();

    for j in 1..n + 1 {
        let xi = horner(&SizedBigInt::new_int(&group, j as isize), &mut coeff);
        let mut hi = GroupElement::new(&group);
        hi = hi.pow(&xi);
        h.push(hi);

        shares.push(xi);
    }

    (shares, h)
}

/*
    evaluate polynomial defined by the vector of coefficients a at point x
*/
pub fn eval_pol(x: &SizedBigInt, a: &Vec<SizedBigInt>) -> SizedBigInt {
    let len = (a.len()) as i32;
    let group = x.get_group();
    let mut val = SizedBigInt::new_int(&group, 0);
    let q = group.get_order();

    for i in 0..len - 1 {
        let mut tmp = SizedBigInt::new_copy(&a[i as usize].clone());
        let mut xi = x.clone();

        xi = xi.pow_mod(&SizedBigInt::new_int(&group, (len - i - 1) as isize), &q);
        tmp = tmp.mul_mod(&xi, &group.get_order());
        val = val.add(&tmp).rmod(&q);
    }

    val = val.add(&a[(len - 1) as usize]).rmod(&q);

    val
}

/*
    faster way to evaluate polynomials, source https://en.wikipedia.org/wiki/Horner%27s_method
*/
pub fn horner(x: &SizedBigInt, a: &Vec<SizedBigInt>) -> SizedBigInt {
    let mut result = a[0].clone(); // Initialize result
    let order = x.get_group().get_order();
    for i in 1..a.len() {
        result = result.mul_mod(&x, &order).add(&a[i]).rmod(&order);
    }

    return result;
}

/* byte-wise xor between two byte vectors */
pub fn xor(v1: Vec<u8>, v2: Vec<u8>) -> Vec<u8> {
    let v3: Vec<u8> = v1.iter().zip(v2.iter()).map(|(&x1, &x2)| x1 ^ x2).collect();

    v3
}

pub fn gen_symm_key(rng: &mut RNG) -> [u8; 32] {
    let prk: &mut [u8] = &mut [0; 32];
    let mut ikm: Vec<u8> = Vec::new();
    for _ in 0..32 {
        ikm.push(rng.getbyte());
    }

    let salt: Vec<u8> = Vec::new();
    hkdf_extract(MC_SHA2, 32, prk, Option::Some(&salt), &ikm);

    let k: &mut [u8; 32] = &mut [0; 32];
    hkdf_expand(MC_SHA2, 32, k, 16, prk, &[0]);

    *k
}

/*
    perform lagrange interpolation over a vector of dl shares
*/
pub fn interpolate<T: DlShare>(shares: &Vec<T>) -> GroupElement {
    let ids: Vec<u16> = (0..shares.len()).map(|x| shares[x].get_id()).collect();
    let mut ry = GroupElement::new(&shares[0].get_group());

    for i in 0..shares.len() {
        let l = lagrange_coeff(&shares[0].get_group(), &ids, shares[i].get_id() as i32);
        let mut ui = shares[i].get_data().clone();
        ui = ui.pow(&l);

        if i == 0 {
            ry = ui;
        } else {
            ry = ry.mul(&ui);
        }
    }

    ry
}

pub fn lagrange_coeff(group: &Group, indices: &[u16], i: i32) -> SizedBigInt {
    let mut prod = SizedBigInt::new_int(group, 1);
    let q = group.get_order();

    for k in 0..indices.len() {
        let j = indices[k] as i32;

        if i != j {
            let mut ij;
            let val = (j - i).abs();

            if i > j {
                ij = q.clone();
                ij = ij.sub(&SizedBigInt::new_int(group, val as isize));
            } else {
                ij = SizedBigInt::new_int(group, val as isize);
            }
            ij = ij.inv_mod(&q);
            ij = ij.mul_mod(&SizedBigInt::new_int(group, j as isize), &q);

            prod = prod.rmod(&q);
            prod = prod.mul_mod(&ij, &q);
        }
    }

    prod = prod.rmod(&q);
    prod
}
