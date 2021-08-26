use crate::*;
use ark_ec::AffineCurve;
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use rand_core::RngCore;
use zeroize::Zeroize;
use miracl_core::ed25519::ecp::ECP;

pub struct EC_Group {
    q: BIG,
}

pub struct PublicKey {
    y: ECP,
    verificationKey: Vec<ECP>,
    g_hat: ECP,
    group: EC_Group,
}

pub struct PrivateKey {
    id: u8,
    xi: BIG,
    pubkey: PublicKey,
}

pub struct Share {
    id: u8,
    data: Vec<u8>,
}