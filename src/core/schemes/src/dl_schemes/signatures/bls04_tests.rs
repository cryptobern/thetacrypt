use theta_proto::scheme_types::Group;

use crate::{keys::{KeyGenerator, PublicKey, PrivateKey}, interface::{ThresholdSignatureParams, ThresholdSignature, SignatureShare, Signature, ThresholdScheme, Serializable}, dl_schemes::dl_groups::bls12381::Bls12381, rand::{RngAlgorithm, RNG}};


#[test]
fn test_key_generation() {
    let keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::OsRng), &ThresholdScheme::Bls04, &Group::Bls12381, &Option::None).unwrap();
    assert!(keys.len() == 5);
}

#[test]
fn test_public_key_serialization() {
    let keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::OsRng), &ThresholdScheme::Bls04, &Group::Bls12381, &Option::None).unwrap();
    let secret_key = keys[0].clone();
    let public_key = secret_key.get_public_key();
    let public_key_encoded = public_key.serialize().unwrap();
    let public_key_decoded = PublicKey::deserialize(&public_key_encoded).unwrap();
    assert!(public_key.eq(&public_key_decoded));
}

#[test]
fn test_secret_key_serialization() {
    let keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::OsRng), &ThresholdScheme::Bls04, &Group::Bls12381, &Option::None).unwrap();
    let secret_key = keys[0].clone();
    let secret_key_encoded = secret_key.serialize().unwrap();
    let secret_key_decoded = PrivateKey::deserialize(&secret_key_encoded).unwrap();
    assert!(secret_key.eq(&secret_key_decoded));
}

#[test]
fn test_signature() {
    let keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::OsRng), &ThresholdScheme::Bls04, &Group::Bls12381, &Option::None).unwrap();
    let mut params = ThresholdSignatureParams::new();
    let msg: Vec<u8> = String::from("plaintext message").as_bytes().to_vec();
    let label = b"Label";
    let sig_share = ThresholdSignature::partial_sign(&msg, label, &keys[0], &mut params).unwrap();
    assert!(true);
}

#[test]
fn test_share_serialization() {
    let keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::OsRng), &ThresholdScheme::Bls04, &Group::Bls12381, &Option::None).unwrap();
    let mut params = ThresholdSignatureParams::new();
    let msg: Vec<u8> = String::from("plaintext message").as_bytes().to_vec();
    let label = b"Label";
    let sig_share = ThresholdSignature::partial_sign(&msg, label, &keys[0], &mut params).unwrap();
    let sig_share_encoded = sig_share.serialize().unwrap();
    let sig_share_decoded = SignatureShare::deserialize(&sig_share_encoded).unwrap();
    assert!(sig_share.eq(&sig_share_decoded));
}

#[test]
fn test_full_scheme() {
    let keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::OsRng), &ThresholdScheme::Bls04, &Group::Bls12381, &Option::None).unwrap();
    let mut params = ThresholdSignatureParams::new();
    let message: Vec<u8> = String::from("plaintext message").as_bytes().to_vec();
    let label = b"Label";
    let mut shares = Vec::new();


    for i in 0..3 {
        shares.push(ThresholdSignature::partial_sign(&message, label,&keys[i as usize], &mut params).unwrap());
        let valid = ThresholdSignature::verify_share(&shares[i as usize], &message, &keys[0].get_public_key());
        assert!(valid.unwrap());
    }

    let sig = ThresholdSignature::assemble(&shares, &message, &keys[0].get_public_key()).unwrap();
    assert!(ThresholdSignature::verify(&sig, &keys[0].get_public_key(), &message).unwrap());

}
#[test]
fn test_signature_serialization() {
    let keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::OsRng), &ThresholdScheme::Bls04, &Group::Bls12381, &Option::None).unwrap();
    let mut params = ThresholdSignatureParams::new();
    let message: Vec<u8> = String::from("plaintext message").as_bytes().to_vec();
    let label = b"Label";
    let mut shares = Vec::new();


    for i in 0..3 {
        shares.push(ThresholdSignature::partial_sign(&message, label,&keys[i as usize], &mut params).unwrap());
        let valid = ThresholdSignature::verify_share(&shares[i as usize], &message, &keys[0].get_public_key()).unwrap();
        assert!(valid);
    }

    let sig = ThresholdSignature::assemble(&shares, &message, &keys[0].get_public_key()).unwrap();
    let sig_encoded = sig.serialize().unwrap();
    let sig_decoded = Signature::deserialize(&sig_encoded).unwrap();
    assert!(sig.eq(&sig_decoded));
}

#[test]
fn test_invalid_share() {
    let keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::OsRng), &ThresholdScheme::Bls04, &Group::Bls12381, &Option::None).unwrap();
    let mut params = ThresholdSignatureParams::new();
    let message: Vec<u8> = String::from("plaintext message").as_bytes().to_vec();
    let label = b"Label";
    let mut shares = Vec::new();
    let keys2 = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::OsRng), &ThresholdScheme::Bls04, &Group::Bls12381, &Option::None).unwrap();

    for i in 0..3 {
        shares.push(ThresholdSignature::partial_sign(&message, label,&keys[i as usize], &mut params).unwrap());
        let valid = ThresholdSignature::verify_share(&shares[i as usize], &message, &keys2[0].get_public_key());
        assert!(!valid.unwrap());
    }
}   

#[test]
fn test_invalid_sig() {
    let keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::OsRng), &ThresholdScheme::Bls04, &Group::Bls12381, &Option::None).unwrap();
    let mut params = ThresholdSignatureParams::new();
    let message: Vec<u8> = String::from("plaintext message").as_bytes().to_vec();
    let label = b"Label";
    let mut shares = Vec::new();
    let keys2 = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::OsRng), &ThresholdScheme::Bls04, &Group::Bls12381, &Option::None).unwrap();

    for i in 0..3 {
        shares.push(ThresholdSignature::partial_sign(&message, label,&keys2[i as usize], &mut params).unwrap());
        let _valid = ThresholdSignature::verify_share(&shares[i as usize], &message, &keys2[0].get_public_key());
    }

    let sig = ThresholdSignature::assemble(&shares, &message, &keys[0].get_public_key()).unwrap();
    assert!(!ThresholdSignature::verify(&sig, &keys[0].get_public_key(), &message).unwrap());
}   