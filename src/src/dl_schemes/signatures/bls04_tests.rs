use crate::{dl_schemes::{DlDomain, dl_groups::{bls12381::{Bls12381, Bls12381ECP2}, dl_group::DlGroup}, signatures::bls04::*}, rand::{RNG, RngAlgorithm}, unwrap_keys, interface::{Serializable, ThresholdSignatureParams, ThresholdSignature, PrivateKey}, util::printbinary};

#[test]
fn test_key_generation() {
    let keys = Bls04ThresholdSignature::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    assert!(keys.len() == 5);
}

#[test]
fn test_public_key_serialization() {
    let keys = Bls04ThresholdSignature::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let secret_key = keys[0].clone();
    let public_key = secret_key.get_public_key();
    let public_key_encoded = public_key.serialize().unwrap();
    let public_key_decoded = Bls04PublicKey::<Bls12381>::deserialize(&public_key_encoded).unwrap();
    assert!(public_key.eq(&public_key_decoded));
}

#[test]
fn test_secret_key_serialization() {
    let keys = Bls04ThresholdSignature::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let secret_key = keys[0].clone();
    let secret_key_encoded = secret_key.serialize().unwrap();
    let secret_key_decoded = Bls04PrivateKey::<Bls12381>::deserialize(&secret_key_encoded).unwrap();
    assert!(secret_key.eq(&secret_key_decoded));
}

#[test]
fn test_signature() {
    let keys = Bls04ThresholdSignature::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let mut params = ThresholdSignatureParams::new();
    let msg: Vec<u8> = String::from("plaintext message").as_bytes().to_vec();
    let label = b"Label";
    let sig_share = Bls04ThresholdSignature::partial_sign(&msg, label, &keys[0], &mut params);
    assert!(true);
}

#[test]
fn test_share_serialization() {
    let keys = Bls04ThresholdSignature::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let mut params = ThresholdSignatureParams::new();
    let msg: Vec<u8> = String::from("plaintext message").as_bytes().to_vec();
    let label = b"Label";
    let sig_share = Bls04ThresholdSignature::partial_sign(&msg, label, &keys[0], &mut params);
    let sig_share_encoded = sig_share.serialize().unwrap();
    let sig_share_decoded = Bls04SignatureShare::<Bls12381>::deserialize(&sig_share_encoded).unwrap();
    assert!(sig_share.eq(&sig_share_decoded));
}

#[test]
fn test_full_scheme() {
    let keys = Bls04ThresholdSignature::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let mut params = ThresholdSignatureParams::new();
    let message: Vec<u8> = String::from("plaintext message").as_bytes().to_vec();
    let label = b"Label";
    let mut shares = Vec::new();


    for i in 0..3 {
        shares.push(Bls04ThresholdSignature::partial_sign(&message, label,&keys[i as usize], &mut params));
        let valid = Bls04ThresholdSignature::verify_share(&shares[i as usize], &message, &keys[0].get_public_key());
        assert!(valid);
    }

    let sig = Bls04ThresholdSignature::assemble(&shares, &message, &keys[0].get_public_key());
    assert!(Bls04ThresholdSignature::verify(&sig, &keys[0].get_public_key()));

}
#[test]
fn test_signature_serialization() {
    let keys = Bls04ThresholdSignature::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let mut params = ThresholdSignatureParams::new();
    let message: Vec<u8> = String::from("plaintext message").as_bytes().to_vec();
    let label = b"Label";
    let mut shares = Vec::new();


    for i in 0..3 {
        shares.push(Bls04ThresholdSignature::partial_sign(&message, label,&keys[i as usize], &mut params));
        let valid = Bls04ThresholdSignature::verify_share(&shares[i as usize], &message, &keys[0].get_public_key());
        assert!(valid);
    }

    let sig = Bls04ThresholdSignature::assemble(&shares, &message, &keys[0].get_public_key());
    let sig_encoded = sig.serialize().unwrap();
    let sig_decoded = Bls04SignedMessage::<Bls12381>::deserialize(&sig_encoded).unwrap();
    assert!(sig.eq(&sig_decoded));
}

#[test]
fn test_invalid_share() {
    let keys = Bls04ThresholdSignature::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman)); 
    let mut params = ThresholdSignatureParams::new();
    let message: Vec<u8> = String::from("plaintext message").as_bytes().to_vec();
    let label = b"Label";
    let mut shares = Vec::new();
    let keys2 = Bls04ThresholdSignature::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));

    for i in 0..3 {
        shares.push(Bls04ThresholdSignature::partial_sign(&message, label,&keys[i as usize], &mut params));
        let valid = Bls04ThresholdSignature::verify_share(&shares[i as usize], &message, &keys2[0].get_public_key());
        assert!(!valid);
    }
}   

#[test]
fn test_invalid_sig() {
    let keys = Bls04ThresholdSignature::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman)); 
    let mut params = ThresholdSignatureParams::new();
    let message: Vec<u8> = String::from("plaintext message").as_bytes().to_vec();
    let label = b"Label";
    let mut shares = Vec::new();
    let keys2 = Bls04ThresholdSignature::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));

    for i in 0..3 {
        shares.push(Bls04ThresholdSignature::partial_sign(&message, label,&keys2[i as usize], &mut params));
        let valid = Bls04ThresholdSignature::verify_share(&shares[i as usize], &message, &keys2[0].get_public_key());
    }

    let sig = Bls04ThresholdSignature::assemble(&shares, &message, &keys[0].get_public_key());
    assert!(!Bls04ThresholdSignature::verify(&sig, &keys[0].get_public_key()));
}   