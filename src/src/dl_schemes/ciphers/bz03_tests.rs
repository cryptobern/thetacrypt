use crate::{interface::{ThresholdCipherParams, ThresholdScheme, ThresholdCipher}, keys::{KeyGenerator, PublicKey, PrivateKey}, rand::{RngAlgorithm, RNG}, group::Group};


#[test]
fn test_public_key_serialization() {
    let private_keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &ThresholdScheme::BZ03, &Group::Bls12381);
    let public_key = private_keys[0].get_public_key();
    assert!(private_keys.len() == 5);

    let public_key_encoded = public_key.serialize().unwrap();
    let public_key_decoded = PublicKey::deserialize(&public_key_encoded).unwrap();
    assert!(public_key.eq(&public_key_decoded));
}

#[test]
fn test_scheme() {
    let mut params = ThresholdCipherParams::new();
    println!("generating keys");
    let private_keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &ThresholdScheme::BZ03, &Group::Bn254);
    let public_key = private_keys[0].get_public_key();
    /* Serialisation usage */

    println!("keys generated");

    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";

    println!("encrypting now");
    let ciphertext = ThresholdCipher::encrypt(&msg, label, &public_key, &mut params).unwrap();
    let mut shares = Vec::new();

    println!("encrypted");
    
    for i in 0..3 {
        shares.push(ThresholdCipher::partial_decrypt(&ciphertext, &private_keys[i as usize], &mut params).unwrap());
        assert!(ThresholdCipher::verify_share(&shares[i], &ciphertext, &public_key).unwrap());
    }

    let decrypted = ThresholdCipher::assemble(&shares, &ciphertext).unwrap();
    assert!(msg.eq(&decrypted));
}

#[test]
fn test_secret_key_serialization() {
    let private_keys = KeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &ThresholdScheme::BZ03, &Group::Bls12381);
    let secret_key = private_keys[0].clone();
    let secret_key_encoded = secret_key.serialize().unwrap();
    let secret_key_decoded = PrivateKey::deserialize(&secret_key_encoded).unwrap();
    assert!(secret_key.eq(&secret_key_decoded));
}

/*

#[test]
fn test_ciphertext_serialization() {
    let keys = Bz03ThresholdCipher::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let mut params = ThresholdCipherParams::new();
    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";
    let ciphertext = Bz03ThresholdCipher::encrypt(&msg, label, &keys[0].get_public_key(), &mut params);
    let ciphertext_encoded = ciphertext.serialize().unwrap();
    let ciphertext_decoded = Bz03Ciphertext::<Bls12381>::deserialize(&ciphertext_encoded).unwrap();
    assert!(ciphertext.eq(&ciphertext_decoded));
}

#[test]
fn test_full_scheme() {
    let keys = Bz03ThresholdCipher::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let mut params = ThresholdCipherParams::new();
    let plaintext: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";
    let mut shares = Vec::new();
    let ciphertext = Bz03ThresholdCipher::encrypt(&plaintext, label, &keys[0].get_public_key(), &mut params);


    for i in 0..3 {
        shares.push(Bz03ThresholdCipher::partial_decrypt(&ciphertext,&keys[i as usize], &mut params));
        let valid = Bz03ThresholdCipher::verify_share(&shares[i as usize], &ciphertext, &keys[0].get_public_key());
        assert!(valid);
    }

    let decrypted = Bz03ThresholdCipher::assemble(&shares, &ciphertext);
    assert_eq!(plaintext, decrypted);

}
#[test]
fn test_share_serialization() {
    let keys = Bz03ThresholdCipher::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));
    let mut params = ThresholdCipherParams::new();
    let msg: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";
    let ciphertext = Bz03ThresholdCipher::encrypt(&msg, label, &keys[0].get_public_key(), &mut params);
    let share = Bz03ThresholdCipher::partial_decrypt(&ciphertext,&keys[0], &mut params);
    let share_encoded = share.serialize().unwrap();
    let share_decoded = Bz03DecryptionShare::<Bls12381ECP2>::deserialize(&share_encoded).unwrap();
    assert!(share.eq(&share_decoded));
}

#[test]
fn test_invalid_share() {
    let keys = Bz03ThresholdCipher::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman)); 
    let mut params = ThresholdCipherParams::new();
    let plaintext: Vec<u8> = String::from("plaintext").as_bytes().to_vec();
    let label = b"Label";
    let mut shares = Vec::new();
    let ciphertext = Bz03ThresholdCipher::encrypt(&plaintext, label, &keys[0].get_public_key(), &mut params);
    let keys2 = Bz03ThresholdCipher::generate_keys(3, 5, Bls12381::new(), &mut RNG::new(RngAlgorithm::MarsagliaZaman));

    for i in 0..3 {
        shares.push(Bz03ThresholdCipher::partial_decrypt(&ciphertext,&keys2[i as usize], &mut params));
        let valid = Bz03ThresholdCipher::verify_share(&shares[i as usize], &ciphertext, &keys[0].get_public_key());
        assert!(!valid);
    }
}*/