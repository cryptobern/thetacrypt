use crate::{dl_schemes::{dl_groups::{bls12381::Bls12381, dl_group::DlGroup}}, rand::{RNG, RngAlgorithm}, unwrap_keys, interface::{Serializable, ThresholdCoin, PrivateKey}, util::printbinary};
use super::cks05::*;


#[test]
fn test_key_generation() {
    let keys = Cks05ThresholdCoin::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    assert!(keys.len() == 5);
}

#[test]
fn test_public_key_serialization() {
    let keys = Cks05ThresholdCoin::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let secret_key = keys[0].clone();
    let public_key = secret_key.get_public_key();
    let public_key_encoded = public_key.serialize().unwrap();
    let public_key_decoded = Cks05PublicKey::<Bls12381>::deserialize(&public_key_encoded).unwrap();
    assert!(public_key.eq(&public_key_decoded));
}

#[test]
fn test_secret_key_serialization() {
    let keys = Cks05ThresholdCoin::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let secret_key = keys[0].clone();
    let secret_key_encoded = secret_key.serialize().unwrap();
    let secret_key_decoded = Cks05PrivateKey::<Bls12381>::deserialize(&secret_key_encoded).unwrap();
    assert!(secret_key.eq(&secret_key_decoded));
}

#[test]
fn test_share_creation() {
    let keys = Cks05ThresholdCoin::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let name = b"Label";
    let share = Cks05ThresholdCoin::create_share(name, &keys[0], &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let valid = Cks05ThresholdCoin::verify_share(&share, name, &keys[0].get_public_key());
    assert!(valid);
}

#[test]
fn test_share_serialization() {
    let keys = Cks05ThresholdCoin::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let name = b"Label";
    let share = Cks05ThresholdCoin::create_share(name, &keys[0], &mut RNG::new(RngAlgorithm::MarsagliaZaman));

    let share_encoded = share.serialize().unwrap();
    let share_decoded = Cks05CoinShare::<Bls12381>::deserialize(&share_encoded).unwrap();

    assert!(share.eq(&share_decoded));
}

#[test]
fn test_full_scheme() {
    let keys = Cks05ThresholdCoin::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let name = b"My Coin";
    let mut shares = Vec::new();

    for i in 0..5 {
        shares.push(Cks05ThresholdCoin::create_share(name,&keys[i as usize], &mut RNG::new(RngAlgorithm::MarsagliaZaman)));
        let valid = Cks05ThresholdCoin::verify_share(&shares[i as usize], name, &keys[0].get_public_key());
        assert!(valid);
    }

    let coin1 = Cks05ThresholdCoin::assemble(&shares[0..3].to_vec());
    let coin2 = Cks05ThresholdCoin::assemble(&shares[1..4].to_vec());
    assert_eq!(coin1, coin2);

}

#[test]
fn test_invalid_share() {
    let keys = Cks05ThresholdCoin::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman)); 
    let name = b"Label";
    let mut shares = Vec::new();
    let keys2 = Cks05ThresholdCoin::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));

    for i in 0..3 {
        shares.push(Cks05ThresholdCoin::create_share(name,&keys2[i as usize], &mut RNG::new(RngAlgorithm::MarsagliaZaman)));
        let valid = Cks05ThresholdCoin::verify_share(&shares[i as usize], name, &keys[0].get_public_key());
        assert!(!valid);
    }
}