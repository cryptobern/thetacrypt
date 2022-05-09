use rand::Rng;

use crate::rand::{RNG, RngAlgorithm};

use super::{bls12381::{Bls12381, Bls12381ECP2, Bls12381FP12}, dl_group::DlGroup, pairing::PairingEngine};



/* BLS12381 */
#[test]
fn test_bls12381_equals() {
    let x = Bls12381::new_rand(&mut RNG::new( RngAlgorithm::MarsagliaZaman));
    let y = Bls12381::new_copy(&x);

    assert!(x.equals(&y))
}

/* BLS12381 ECP2 */
#[test]
fn test_bls12381_ecp2_equals() {
    let x = Bls12381ECP2::new_rand(&mut RNG::new( RngAlgorithm::MarsagliaZaman));
    let y = Bls12381ECP2::new_copy(&x);

    assert!(x.equals(&y))
}

/* BLS12381 FP12 */
#[test]
fn test_bls12381_fp12_equals() {
    let x = Bls12381FP12::new_rand(&mut RNG::new( RngAlgorithm::MarsagliaZaman));
    let y = Bls12381FP12::new_copy(&x);

    assert!(x.equals(&y))
}