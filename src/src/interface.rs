use rasn::{der::{encode, decode}, Encode, Decode};

use crate::{rand::{RNG, RngAlgorithm}, dl_schemes::{ciphers::{sg02::*}, dl_groups::dl_group::{Group, GroupElement}}, keys::{PrivateKey, PublicKey}, unwrap_enum_vec};

pub trait Serializable:
    Sized
    + Clone
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ThresholdScheme {
    BZ03,
    SG02,
    BLS04,
    CKS05,
    FROST,
    SH00
}

pub trait DlShare {
    fn get_id(&self) -> u16;
    fn get_data(&self) -> GroupElement;
    fn get_group(&self) -> Group;
}

/* Threshold Signatures */

pub struct ThresholdSignature {}

impl ThresholdSignature {
    /*
    fn verify(sig: &Self::TSig, TPubKey: &PublicKey) -> bool;
    fn partial_sign(msg: &[u8], label: &[u8], TPrivKey: &Self::TPrivKey, params: &mut ThresholdSignatureParams) -> Self::TShare;
    fn verify_share(share: &Self::TShare, msg: &[u8], TPubKey: &PublicKey) -> bool;
    fn assemble(shares: &Vec<Self::TShare>, msg: &[u8], TPubKey: &PublicKey) -> Self::TSig; */
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


/* Threshold Coin */
pub struct ThresholdCoin {}

impl ThresholdCoin {
    /*
    fn create_share(name: &[u8], TPrivKey: &Self::TPrivKey, rng: &mut RNG) -> Self::TShare;
    fn verify_share(share: &Self::TShare, name: &[u8], TPubKey: &PublicKey) -> bool;
    fn assemble(shares: &Vec<Self::TShare>) -> u8;
    */
}


/*
    TODO: change library structure from using generics for group to unions and group_id
    TODO: create unified key, share and signature structs
*/


/* ---- NEW API ---- */

#[derive(PartialEq)]
pub enum Ciphertext {
    SG02(Sg02Ciphertext)
}

impl Ciphertext {
    pub fn get_msg(&self) -> Vec<u8> {
        match self {
            Ciphertext::SG02(ct) => ct.get_msg(),
            _ => todo!()
        }
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Ciphertext::SG02(ct) => ct.get_scheme(),
            _ => todo!()
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            Ciphertext::SG02(ct) => ct.get_group(),
            _ => todo!()
        }
    }

    pub fn get_label(&self) -> Vec<u8> {
        match self {
            Ciphertext::SG02(ct) => ct.get_label(),
            _ => todo!()
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, rasn::ber::enc::Error> {
        match self {
            Ciphertext::SG02(ct) => ct.serialize()
        }
    }

    pub fn deserialize(bytes: &Vec<u8>) -> Self {
        //TODO: fix
        Ciphertext::SG02(Sg02Ciphertext::deserialize(bytes).unwrap())
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Ciphertext::SG02(_) => ThresholdScheme::SG02,
            _ => todo!()
        }
    }
}

pub struct ThresholdCipher {}

#[derive(PartialEq)]
pub enum DecryptionShare {
    SG02(Sg02DecryptionShare)
}

impl ThresholdCipher {
    pub fn encrypt(msg: &[u8], label: &[u8], pubkey: &PublicKey, params: &mut ThresholdCipherParams) -> Result<Ciphertext, TcError> {
        match pubkey {
            PublicKey::SG02(key) => {
                Ok(Ciphertext::SG02(Sg02ThresholdCipher::encrypt(msg, label, key, params)))
            }
        }
    }
    
    pub fn verify_ciphertext(ct: &Ciphertext, pubkey: &PublicKey) -> Result<bool, TcError> {
        match ct {
            Ciphertext::SG02(ct) => {
                match pubkey {
                    PublicKey::SG02(key) => {
                        Ok(Sg02ThresholdCipher::verify_ciphertext(ct, key))
                    }, 
                    _ => {
                        Err(TcError::WrongKeyProvided)
                    }
                }
            }
        }
    }
    
    pub fn verify_share(share: &DecryptionShare, ct: &Ciphertext, pubkey: &PublicKey) -> Result<bool, TcError> {
        match ct {
            Ciphertext::SG02(ct) => {

                match share {
                    DecryptionShare::SG02(s) => {
                        match pubkey {
                            PublicKey::SG02(key) => {
                                Ok(Sg02ThresholdCipher::verify_share(s, ct, key))
                            }, 
                            _ => {
                                Err(TcError::WrongKeyProvided)
                            }
                        }
                    },
                    _ => {
                        Err(TcError::IncompatibleSchemes)
                    }
                }
            }
        }
    }

    pub fn partial_decrypt(ct: &Ciphertext, privkey: &PrivateKey, params: &mut ThresholdCipherParams) -> Result<DecryptionShare, TcError> {
        match ct {
            Ciphertext::SG02(ct) => {
                match privkey {
                    PrivateKey::SG02(key) => {
                        Ok(DecryptionShare::SG02(Sg02ThresholdCipher::partial_decrypt(ct, key, params)))
                    }, 
                    _ => {
                        Err(TcError::WrongKeyProvided)
                    }
                }
            }
        }
    }

    pub fn assemble(shares: &Vec<DecryptionShare>, ct: &Ciphertext) -> Result<Vec<u8>, TcError> {
        match ct {
            Ciphertext::SG02(ct) => {
                let shares = unwrap_enum_vec!(shares, DecryptionShare::SG02, TcError::IncompatibleSchemes);

                if shares.is_ok() {
                    return Ok(Sg02ThresholdCipher::assemble(&shares.unwrap(), ct));
                }

                Err(shares.err().unwrap())
            }
        }
    }

}

impl DecryptionShare {
    pub fn get_id(&self) -> u16 {
        match self {
            Self::SG02(share) => share.get_id(),
            _ => todo!()
        }
    }

    pub fn get_label(&self) -> Vec<u8> {
        match self {
            DecryptionShare::SG02(share) => share.get_label(),
            _ => todo!()
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            Self::SG02(share) => share.get_group(),
            _ => todo!()
        }
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Self::SG02(share) => share.get_scheme(),
            _ => todo!()
        }
    }

    pub fn get_data(&self) -> GroupElement {
        match self {
            Self::SG02(share) => share.get_data(),
            _ => todo!()
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, rasn::ber::enc::Error> {
        match self {
            DecryptionShare::SG02(s) => s.serialize()
        }
    }

    pub fn deserialize(bytes: &Vec<u8>) -> Self {
        //TODO: fix
        DecryptionShare::SG02(Sg02DecryptionShare::deserialize(bytes).unwrap())
    }
}

#[derive(Debug)]
pub enum TcError {
    IncompatibleGroups,
    IncompatibleSchemes,
    WrongKeyProvided
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