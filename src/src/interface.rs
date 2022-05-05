use rasn::{der::{encode, decode}, Encode, Decode};

use crate::rand::{RNG, RngAlgorithm};

pub trait PublicKey:
    Serializable {
}

pub trait PrivateKey:
    Serializable {
    type TPubKey: PublicKey;
    fn get_id(&self) -> u32;
    fn get_public_key(&self) -> Self::TPubKey;
}

pub trait Ciphertext:
    Serializable {
    fn get_msg(&self) -> Vec<u8>;
    fn get_label(&self) -> Vec<u8>;
}
pub trait Share:
    Serializable {
    fn get_id(&self) -> u32;
}

pub trait Serializable:
    Sized
    + Encode
    + Decode
    + PartialEq {
    fn serialize(&self) -> Result<Vec<u8>, rasn::ber::enc::Error> {
        encode(self)
    }
    fn deserialize(bytes: &Vec<u8>) -> Result<Self, rasn::ber::de::Error>  {
        decode(bytes)
    }
}

pub trait ThresholdCipher {
    type CT: Ciphertext;
    type TPubKey: PublicKey;
    type TPrivKey: PrivateKey;
    type TShare: Share;

    fn encrypt(msg: &[u8], label: &[u8], TPubKey: &Self::TPubKey, params: &mut ThresholdCipherParams) -> Self::CT;
    fn verify_ciphertext(ct: &Self::CT, TPubKey: &Self::TPubKey) -> bool;
    fn verify_share(share: &Self::TShare, ct: &Self::CT, TPubKey: &Self::TPubKey) -> bool;
    fn partial_decrypt(ct: &Self::CT, TPrivKey: &Self::TPrivKey, params: &mut ThresholdCipherParams) -> Self::TShare;
    fn assemble(shares: &Vec<Self::TShare>, ct: &Self::CT) -> Vec<u8>;
}

pub trait ThresholdSignature {
    type TSig;
    type TPubKey: PublicKey;
    type TPrivKey: PrivateKey;
    type TShare: Share;

    fn verify(sig: &Self::TSig, TPubKey: &Self::TPubKey) -> bool;
    fn partial_sign(msg: &[u8], label: &[u8], TPrivKey: &Self::TPrivKey, params: &mut ThresholdSignatureParams) -> Self::TShare;
    fn verify_share(share: &Self::TShare, msg: &[u8], TPubKey: &Self::TPubKey) -> bool;
    fn assemble(shares: &Vec<Self::TShare>, msg: &[u8], TPubKey: &Self::TPubKey) -> Self::TSig;
}

pub trait ThresholdCoin {
    type TPubKey: PublicKey;
    type TPrivKey: PrivateKey;
    type TShare: Share;

    fn create_share(name: &[u8], TPrivKey: &Self::TPrivKey, rng: &mut RNG) -> Self::TShare;
    fn verify_share(share: &Self::TShare, name: &[u8], TPubKey: &Self::TPubKey) -> bool;
    fn assemble(shares: &Vec<Self::TShare>) -> u8;
}

pub struct ThresholdCipherParams {
    pub rng: RNG,
}

impl ThresholdCipherParams {
    pub fn new() -> Self { 
        let rng = RNG::new(crate::rand::RngAlgorithm::MarsagliaZaman);
        Self { rng }
    }

    pub fn set_rng(&mut self, alg: RngAlgorithm) {
        self.rng = RNG::new(alg);
    }
}

pub struct ThresholdSignatureParams {
    pub rng: RNG,
}

impl ThresholdSignatureParams {
    pub fn new() -> Self { 
        let rng = RNG::new(crate::rand::RngAlgorithm::MarsagliaZaman);
        Self { rng }
    }

    pub fn set_rng(&mut self, alg: RngAlgorithm) {
        self.rng = RNG::new(alg);
    }
}