use rasn::der::{encode, decode};
use crate::{rand::{RngAlgorithm, RNG}, interface::Serializable};

use super::{ciphers::{sg02::Sg02ThresholdCipher, bz03::Bz03PrivateKey}, dl_groups::{bls12381::Bls12381, dl_group::DlGroup, ed25519::Ed25519, bn254::Bn254}, keygen::{DlKeyGenerator, DlScheme, DlPrivateKey}, pkcs8::{Pkcs8PrivateKeyInfo, AlgorithmIdentifier}, DlDomain};


#[test]
fn test_key_serilialization() {
    let mut rng = &mut RNG::new(RngAlgorithm::MarsagliaZaman);
    let keys = DlKeyGenerator::generate_keys(3, 5, rng, &DlScheme::BLS04(Bls12381::new()));
    let encoded = encode(&keys[0]).unwrap();
    let decoded: DlPrivateKey<Bls12381> = decode(&encoded).unwrap();
    match decoded {
        DlPrivateKey::BLS04(key) => {
            println!("Decoded BLS04 private key!");
        }, 
        _ => {
            println!("Deserialized invalid private key");
            assert!(1==0);
        }
    }
}