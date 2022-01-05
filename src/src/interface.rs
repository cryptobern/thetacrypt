use mcore::rand::{RAND};

pub trait PublicKey {}

pub trait PrivateKey {
    type PK: PublicKey;
    fn get_id(&self) -> usize;
    fn get_public_key(&self) -> Self::PK;
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
    type PK: PublicKey;
    type SK: PrivateKey;
    type SH: Share;

    fn encrypt(msg: &[u8], label: &[u8], pk: &Self::PK, rng: &mut impl RAND) -> Self::CT;
    fn verify_ciphertext(ct: &Self::CT, pk: &Self::PK) -> bool;
    fn verify_share(share: &Self::SH, ct: &Self::CT, pk: &Self::PK) -> bool;
    fn partial_decrypt(ct: &Self::CT, sk: &Self::SK, rng: &mut impl RAND) -> Self::SH;
    fn assemble(shares: &Vec<Self::SH>, ct: &Self::CT) -> Vec<u8>;
}

pub trait ThresholdSignature {
    type SM;
    type PK: PublicKey;
    type SK: PrivateKey;
    type SH: Share;

    fn verify(sig: &Self::SM, pk: &Self::PK) -> bool;
    fn partial_sign(msg: &[u8], sk: &Self::SK) -> Self::SH;
    fn verify_share(share: &Self::SH, msg: &[u8], pk: &Self::PK) -> bool;
    fn assemble(shares: &Vec<Self::SH>, msg: &[u8], pk: &Self::PK) -> Self::SM;
}

pub trait ThresholdCoin {
    type PK: PublicKey;
    type SK: PrivateKey;
    type SH: Share;

    fn create_share(name: &[u8], sk: &Self::SK, rng: &mut impl RAND) -> Self::SH;
    fn verify_share(share: &Self::SH, name: &[u8], pk: &Self::PK) -> bool;
    fn assemble(shares: &Vec<Self::SH>) -> u8;
}