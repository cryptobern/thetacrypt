use crate::rand::RNG;

pub trait PublicKey {}

pub trait PrivateKey {
    type TPubKey: PublicKey;
    fn get_id(&self) -> usize;
    fn get_public_key(&self) -> Self::TPubKey;
}

pub trait Ciphertext {
    fn get_msg(&self) -> Vec<u8>;
    fn get_label(&self) -> Vec<u8>;
}
pub trait Share {
    fn get_id(&self) -> usize;
}
pub trait ThresholdCipher {
    type CT: Ciphertext;
    type TPubKey: PublicKey;
    type TPrivKey: PrivateKey;
    type TShare: Share;
    type TParams;

    fn encrypt(msg: &[u8], label: &[u8], TPubKey: &Self::TPubKey, rng: &mut RNG) -> Self::CT;
    fn verify_ciphertext(ct: &Self::CT, TPubKey: &Self::TPubKey) -> bool;
    fn verify_share(share: &Self::TShare, ct: &Self::CT, TPubKey: &Self::TPubKey) -> bool;
    fn partial_decrypt(ct: &Self::CT, TPrivKey: &Self::TPrivKey, params: Option<&mut Self::TParams>) -> Self::TShare;
    fn assemble(shares: &Vec<Self::TShare>, ct: &Self::CT) -> Vec<u8>;
}

pub trait ThresholdSignature {
    type TSig;
    type TPubKey: PublicKey;
    type TPrivKey: PrivateKey;
    type TShare: Share;
    type TParams;

    fn verify(sig: &Self::TSig, TPubKey: &Self::TPubKey) -> bool;
    fn partial_sign(msg: &[u8], label: &[u8], TPrivKey: &Self::TPrivKey, params: Option<&mut Self::TParams>) -> Self::TShare;
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