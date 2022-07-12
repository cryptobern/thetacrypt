use rasn::der::{encode, decode};
use crate::{rand::{RngAlgorithm, RNG}, interface::Serializable};

//use super::{ciphers::{sg02::Sg02ThresholdCipher, bz03::Bz03PrivateKey}, dl_groups::{bls12381::Bls12381, dl_group::DlGroup, ed25519::Ed25519, bn254::Bn254}, keygen::{DlKeyGenerator, DlScheme, DlPrivateKey}, pkcs8::{Pkcs8PrivateKeyInfo, AlgorithmIdentifier}, DlDomain};


/*#[test]
fn test_key_serilialization() {
    let mut rng = &mut RNG::new(RngAlgorithm::MarsagliaZaman);
    let keys = DlKeyGenerator::generate_keys(3, 5, rng, &DlScheme::BLS04(Bls12381::new()));
    let encoded = encode(&keys[0]).unwrap();
    let decoded: DlPrivateKey<Bls12381> = decode(&encoded).unwrap();
    match decoded {
        DlPrivateKey::BLS04(key) => {
            println!("Decoded Bz03 private key!");
        }, 
        _ => {
            println!("Deserialized invalid private key");
            assert!(1==0);
        }
    }
}*/
/*
#[test]
fn test_pkcs8() {
    let keys = DlKeyGenerator::generate_keys(3, 5, &mut RNG::new(RngAlgorithm::MarsagliaZaman), &DlScheme::BZ03(Bls12381::new()));
    let encoded = Pkcs8PrivateKeyInfo::encodePrivateKey(&keys[0]);


    let (identifier, bytes) = Pkcs8PrivateKeyInfo::decodeParams(&encoded);
    match identifier {
        AlgorithmIdentifier::BZ03_BLS12381 => {
            let key = Bz03PrivateKey::<Bls12381>::deserialize(&bytes).unwrap();
        },

        AlgorithmIdentifier::BZ03_BN254 => {
            let key = Bz03PrivateKey::<Bn254>::deserialize(&bytes).unwrap();
        },

        AlgorithmIdentifier::BZ03_ED25519 => {
            let key = Bz03PrivateKey::<Ed25519>::deserialize(&bytes).unwrap();
        },
        _ => {
            panic!("Invalid identifier");
        }
    }
}*/