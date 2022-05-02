use crate::{dl_schemes::{DlDomain, dl_groups::{bls12381::Bls12381, dl_group::DlGroup}}, rand::{RNG, RngAlgorithm}, unwrap_keys, interface::{Serializable, ThresholdCipherParams, ThresholdCipher, PrivateKey}, util::printbinary};
use super::sg02::*;


#[test]
fn test_key_generation() {
    let keys = Sg02ThresholdCipher::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    assert!(keys.len() == 5);
}

#[test]
fn test_public_key_serialization() {
    let keys = Sg02ThresholdCipher::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let secret_key = keys[0].clone();
    let public_key = secret_key.get_public_key();
    let public_key_encoded = public_key.serialize().unwrap();
    let public_key_decoded = Sg02PublicKey::<Bls12381>::deserialize(public_key_encoded).unwrap();
    assert!(public_key.eq(&public_key_decoded));
}

#[test]
fn test_secret_key_serialization() {
    let keys = Sg02ThresholdCipher::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let secret_key = keys[0].clone();
    let secret_key_encoded = secret_key.serialize().unwrap();
    let secret_key_decoded = Sg02PrivateKey::<Bls12381>::deserialize(secret_key_encoded).unwrap();
    assert!(secret_key.eq(&secret_key_decoded));
}

#[test]
fn test_encryption() {
    let keys = Sg02ThresholdCipher::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let mut params = ThresholdCipherParams::new();
    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";
    let ciphertext = Sg02ThresholdCipher::encrypt(&msg, label, &keys[0].get_public_key(), &mut params);
    assert!(true);
}

#[test]
fn test_ciphertext_serialization() {
    let keys = Sg02ThresholdCipher::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let mut params = ThresholdCipherParams::new();
    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";
    let ciphertext = Sg02ThresholdCipher::encrypt(&msg, label, &keys[0].get_public_key(), &mut params);
    let ciphertext_encoded = ciphertext.serialize().unwrap();
    let ciphertext_decoded = Sg02Ciphertext::<Bls12381>::deserialize(ciphertext_encoded).unwrap();
    assert!(ciphertext.eq(&ciphertext_decoded));
}

#[test]
fn test_full_scheme() {
    let keys = Sg02ThresholdCipher::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let mut params = ThresholdCipherParams::new();
    let plaintext: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";
    let mut shares = Vec::new();
    let ciphertext = Sg02ThresholdCipher::encrypt(&plaintext, label, &keys[0].get_public_key(), &mut params);


    for i in 0..3 {
        shares.push(Sg02ThresholdCipher::partial_decrypt(&ciphertext,&keys[i as usize], &mut params));
        let valid = Sg02ThresholdCipher::verify_share(&shares[i as usize], &ciphertext, &keys[0].get_public_key());
        assert!(valid);
    }

    let decrypted = Sg02ThresholdCipher::assemble(&shares, &ciphertext);
    assert_eq!(plaintext, decrypted);

}
#[test]
fn test_share_serialization() {
    let keys = Sg02ThresholdCipher::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let mut params = ThresholdCipherParams::new();
    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";
    let ciphertext = Sg02ThresholdCipher::encrypt(&msg, label, &keys[0].get_public_key(), &mut params);
    let share = Sg02ThresholdCipher::partial_decrypt(&ciphertext,&keys[0], &mut params);
    let share_encoded = share.serialize().unwrap();
    let share_decoded = Sg02DecryptionShare::<Bls12381>::deserialize(share_encoded).unwrap();
    assert!(share.eq(&share_decoded));
}

#[test]
fn test_invalid_share() {
    let keys = Sg02ThresholdCipher::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman)); 
    let mut params = ThresholdCipherParams::new();
    let plaintext: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";
    let mut shares = Vec::new();
    let ciphertext = Sg02ThresholdCipher::encrypt(&plaintext, label, &keys[0].get_public_key(), &mut params);
    let keys2 = Sg02ThresholdCipher::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));

    for i in 0..3 {
        shares.push(Sg02ThresholdCipher::partial_decrypt(&ciphertext,&keys2[i as usize], &mut params));
        let valid = Sg02ThresholdCipher::verify_share(&shares[i as usize], &ciphertext, &keys[0].get_public_key());
        assert!(!valid);
    }
}