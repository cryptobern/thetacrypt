use rasn::{der::{encode, decode}, Encode, Decode, Encoder, AsnType};

use crate::{rand::{RNG, RngAlgorithm}, dl_schemes::{ciphers::{sg02::*, bz03::{Bz03ThresholdCipher, Bz03Ciphertext, Bz03DecryptionShare}}, signatures::bls04::{Bls04SignatureShare, Bls04SignedMessage, Bls04ThresholdSignature}}, keys::{PrivateKey, PublicKey}, unwrap_enum_vec, group::{GroupElement, Group}};

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

impl ThresholdScheme {
    pub fn get_id(&self) -> u8 {
        match self {
            Self::BZ03 => 0,
            Self::SG02 => 1,
            Self::BLS04 => 2,
            Self::CKS05 => 3,
            Self::FROST => 4,
            Self::SH00 => 5,
            Self::FROST => 6
        }
    }

    pub fn from_id(id: u8) -> ThresholdScheme {
        match id {
            0 => Self::BZ03,
            1 => Self::SG02,
            2 => Self::BLS04,
            3 => Self::CKS05,
            4 => Self::FROST,
            5 => Self::SH00,
            6 => Self::FROST,
            _ => panic!("unknown scheme id")
        }
    }
}

pub trait DlShare {
    fn get_id(&self) -> u16;
    fn get_data(&self) -> GroupElement;
    fn get_group(&self) -> Group;
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

#[derive(PartialEq, AsnType)]
#[rasn(enumerated)]
pub enum Ciphertext {
    SG02(Sg02Ciphertext),
    BZ03(Bz03Ciphertext)
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
        encode(self)
    }

    pub fn deserialize(bytes: &Vec<u8>) -> Result<Self, ThresholdCryptoError> {
        let ct = decode::<Self>(bytes);
        if ct.is_err() {
            return Err(ThresholdCryptoError::DeserializationFailed)
        }

        return Ok(ct.unwrap());
    }
}

impl Encode for Ciphertext {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        match self  {
            Self::SG02(ct) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::SG02)).encode(sequence)?;
                    ct.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::BZ03(ct) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::BZ03)).encode(sequence)?;
                    ct.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
        }
    }
}

impl Decode for Ciphertext {
    fn decode_with_tag<Dec: rasn::Decoder>(decoder: &mut Dec, tag: rasn::Tag) -> Result<Self, Dec::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let scheme = ThresholdScheme::from_id(u8::decode(sequence)?);
            let bytes = Vec::<u8>::decode(sequence)?;

            match scheme {
                ThresholdScheme::SG02 => {
                    let key: Sg02Ciphertext = decode(&bytes).unwrap();
                    Ok(Ciphertext::SG02(key))
                }, 
                ThresholdScheme::BZ03 => {
                    let key: Bz03Ciphertext = decode(&bytes).unwrap();
                    Ok(Ciphertext::BZ03(key))
                }, 
                _ => {
                    panic!("invalid scheme!");
                }
            }
        })
    }
}

pub struct ThresholdCipher {}

#[derive(PartialEq, AsnType)]
#[rasn(enumerated)]
pub enum DecryptionShare {
    SG02(Sg02DecryptionShare),
    BZ03(Bz03DecryptionShare),
}

impl ThresholdCipher {
    pub fn encrypt(msg: &[u8], label: &[u8], pubkey: &PublicKey, params: &mut ThresholdCipherParams) -> Result<Ciphertext, ThresholdCryptoError> {
        match pubkey {
            PublicKey::SG02(key) => {
                Ok(Ciphertext::SG02(Sg02ThresholdCipher::encrypt(msg, label, key, params)))
            },
            PublicKey::BZ03(key) => {
                Ok(Ciphertext::BZ03(Bz03ThresholdCipher::encrypt(msg, label, key, params)))
            },
            _ => Err(ThresholdCryptoError::WrongKeyProvided)
        }
    }
    
    pub fn verify_ciphertext(ct: &Ciphertext, pubkey: &PublicKey) -> Result<bool, ThresholdCryptoError> {
        match ct {
            Ciphertext::SG02(ct) => {
                match pubkey {
                    PublicKey::SG02(key) => {
                        Ok(Sg02ThresholdCipher::verify_ciphertext(ct, key))
                    }, 
                    _ => {
                        Err(ThresholdCryptoError::WrongKeyProvided)
                    }
                }
            },

            Ciphertext::BZ03(ct) => {
                match pubkey {
                    PublicKey::BZ03(key) => {
                        Bz03ThresholdCipher::verify_ciphertext(ct, key)
                    }, 
                    _ => {
                        Err(ThresholdCryptoError::WrongKeyProvided)
                    }
                }
            },
            _ => Err(ThresholdCryptoError::WrongKeyProvided)
        }
    }
    
    pub fn verify_share(share: &DecryptionShare, ct: &Ciphertext, pubkey: &PublicKey) -> Result<bool, ThresholdCryptoError> {
        match ct {
            Ciphertext::SG02(ct) => {

                match share {
                    DecryptionShare::SG02(s) => {
                        match pubkey {
                            PublicKey::SG02(key) => {
                                Ok(Sg02ThresholdCipher::verify_share(s, ct, key))
                            }, 
                            _ => {
                                Err(ThresholdCryptoError::WrongKeyProvided)
                            }
                        }
                    },
                    _ => {
                        Err(ThresholdCryptoError::WrongScheme)
                    }
                }
            },

            Ciphertext::BZ03(ct) => {
                match share {
                    DecryptionShare::BZ03(s) => {
                        match pubkey {
                            PublicKey::BZ03(key) => {
                                Bz03ThresholdCipher::verify_share(s, ct, key)
                            }, 
                            _ => {
                                Err(ThresholdCryptoError::WrongKeyProvided)
                            }
                        }
                    },
                    _ => {
                        Err(ThresholdCryptoError::WrongScheme)
                    }
                }
            },
            _ => Err(ThresholdCryptoError::WrongKeyProvided)
        }
    }

    pub fn partial_decrypt(ct: &Ciphertext, privkey: &PrivateKey, params: &mut ThresholdCipherParams) -> Result<DecryptionShare, ThresholdCryptoError> {
        match ct {
            Ciphertext::SG02(ct) => {
                match privkey {
                    PrivateKey::SG02(key) => {
                        Ok(DecryptionShare::SG02(Sg02ThresholdCipher::partial_decrypt(ct, key, params)))
                    }, 
                    _ => {
                        Err(ThresholdCryptoError::WrongKeyProvided)
                    }
                }
            },
            Ciphertext::BZ03(ct) => {
                match privkey {
                    PrivateKey::BZ03(key) => {
                        Ok(DecryptionShare::BZ03(Bz03ThresholdCipher::partial_decrypt(ct, key, params)))
                    }, 
                    _ => {
                        Err(ThresholdCryptoError::WrongKeyProvided)
                    }
                }
            },
            _ => Err(ThresholdCryptoError::WrongKeyProvided)
        }
    }

    pub fn assemble(shares: &Vec<DecryptionShare>, ct: &Ciphertext) -> Result<Vec<u8>, ThresholdCryptoError> {
        match ct {
            Ciphertext::SG02(ct) => {
                let shares = unwrap_enum_vec!(shares, DecryptionShare::SG02, ThresholdCryptoError::WrongScheme);

                if shares.is_ok() {
                    return Ok(Sg02ThresholdCipher::assemble(&shares.unwrap(), ct));
                }

                Err(shares.err().unwrap())
            },
            Ciphertext::BZ03(ct) => {
                let shares = unwrap_enum_vec!(shares, DecryptionShare::BZ03, ThresholdCryptoError::WrongScheme);

                if shares.is_ok() {
                    return Ok(Bz03ThresholdCipher::assemble(&shares.unwrap(), ct));
                }

                Err(shares.err().unwrap())
            },
            _ => Err(ThresholdCryptoError::WrongKeyProvided)
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
        encode(self)
    }

    pub fn deserialize(bytes: &Vec<u8>) -> Result<Self, ThresholdCryptoError> {
        let share = decode::<Self>(bytes);
        if share.is_err() {
            return Err(ThresholdCryptoError::DeserializationFailed)
        }

        return Ok(share.unwrap());
    }
}

impl Decode for DecryptionShare {
    fn decode_with_tag<Dec: rasn::Decoder>(decoder: &mut Dec, tag: rasn::Tag) -> Result<Self, Dec::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let scheme = ThresholdScheme::from_id(u8::decode(sequence)?);
            let bytes = Vec::<u8>::decode(sequence)?;

            match scheme {
                ThresholdScheme::SG02 => {
                    let key: Sg02DecryptionShare = decode(&bytes).unwrap();
                    Ok(DecryptionShare::SG02(key))
                }, 
                ThresholdScheme::BZ03 => {
                    let key: Bz03DecryptionShare = decode(&bytes).unwrap();
                    Ok(DecryptionShare::BZ03(key))
                }, 
                _ => {
                    panic!("invalid scheme!");
                }
            }
        })
    }
}

impl Encode for DecryptionShare {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        match self  {
            Self::SG02(share) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::SG02)).encode(sequence)?;
                    share.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::BZ03(share) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::BZ03)).encode(sequence)?;
                    share.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            }
        }
    }
}


/* Threshold Signatures */

#[derive(PartialEq, AsnType)]
#[rasn(enumerated)]
pub enum SignatureShare {
    BLS04(Bls04SignatureShare),
}

impl SignatureShare {
    pub fn get_id(&self) -> u16 {
        match self {
            Self::BLS04(share) => share.get_id(),
            _ => todo!()
        }
    }

    pub fn get_label(&self) -> Vec<u8> {
        match self {
            Self::BLS04(share) => share.get_label(),
            _ => todo!()
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            Self::BLS04(share) => share.get_group(),
            _ => todo!()
        }
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Self::BLS04(share) => share.get_scheme(),
            _ => todo!()
        }
    }

    pub fn get_data(&self) -> GroupElement {
        match self {
            Self::BLS04(share) => share.get_data(),
            _ => todo!()
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, rasn::ber::enc::Error> {
        encode(self)
    }

    pub fn deserialize(bytes: &Vec<u8>) -> Result<Self, ThresholdCryptoError> {
        let share = decode::<Self>(bytes);
        if share.is_err() {
            return Err(ThresholdCryptoError::DeserializationFailed)
        }

        return Ok(share.unwrap());
    }
}

impl Decode for SignatureShare {
    fn decode_with_tag<Dec: rasn::Decoder>(decoder: &mut Dec, tag: rasn::Tag) -> Result<Self, Dec::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let scheme = ThresholdScheme::from_id(u8::decode(sequence)?);
            let bytes = Vec::<u8>::decode(sequence)?;

            match scheme {
                ThresholdScheme::BLS04 => {
                    let share: Bls04SignatureShare = decode(&bytes).unwrap();
                    Ok(SignatureShare::BLS04(share))
                }, 
                _ => {
                    panic!("invalid scheme!");
                }
            }
        })
    }
}

impl Encode for SignatureShare {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        match self  {
            Self::BLS04(share) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::BLS04)).encode(sequence)?;
                    share.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
        }
    }
}

#[derive(AsnType, PartialEq)]
#[rasn(enumerated)]
pub enum SignedMessage {
    BLS04(Bls04SignedMessage),
}

impl SignedMessage {
    pub fn serialize(&self) -> Result<Vec<u8>, rasn::ber::enc::Error> {
        encode(self)
    }

    pub fn deserialize(bytes: &Vec<u8>) -> Result<Self, ThresholdCryptoError> {
        let share = decode::<Self>(bytes);
        if share.is_err() {
            return Err(ThresholdCryptoError::DeserializationFailed)
        }

        return Ok(share.unwrap());
    }
}

impl Decode for SignedMessage {
    fn decode_with_tag<Dec: rasn::Decoder>(decoder: &mut Dec, tag: rasn::Tag) -> Result<Self, Dec::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let scheme = ThresholdScheme::from_id(u8::decode(sequence)?);
            let bytes = Vec::<u8>::decode(sequence)?;

            match scheme {
                ThresholdScheme::BLS04 => {
                    let share: Bls04SignedMessage = decode(&bytes).unwrap();
                    Ok(SignedMessage::BLS04(share))
                }, 
                _ => {
                    panic!("invalid scheme!");
                }
            }
        })
    }
}

impl Encode for SignedMessage {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        match self  {
            Self::BLS04(share) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::BLS04)).encode(sequence)?;
                    share.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
        }
    }
}

pub struct ThresholdSignature {}

impl ThresholdSignature {
    pub fn verify(sig: &SignedMessage, pubkey: &PublicKey) -> Result<bool, ThresholdCryptoError> {
        match sig {
            SignedMessage::BLS04(s) => {
                match pubkey {
                    PublicKey::BLS04(key) => Bls04ThresholdSignature::verify(s, key),
                _ => Result::Err(ThresholdCryptoError::WrongKeyProvided)
                }
            }
        }
    }

    pub fn partial_sign(msg: &[u8], label: &[u8], secret: &PrivateKey, params: &mut ThresholdSignatureParams) -> Result<SignatureShare, ThresholdCryptoError>  {
        match secret {
            PrivateKey::BLS04(s) => {
                Result::Ok(SignatureShare::BLS04(Bls04ThresholdSignature::partial_sign(msg, label,s, params)))
            },
            _ => Result::Err(ThresholdCryptoError::WrongKeyProvided)
        }
    }

    pub fn verify_share(share: &SignatureShare, msg: &[u8], pubkey: &PublicKey) -> Result<bool, ThresholdCryptoError>  {
        match share {
            SignatureShare::BLS04(s) => {
                match pubkey {
                    PublicKey::BLS04(key) => Bls04ThresholdSignature::verify_share(s, msg, key),
                _ => Result::Err(ThresholdCryptoError::WrongKeyProvided)
                }
            }
        }
    }

    pub fn assemble(shares: &Vec<SignatureShare>, msg: &[u8], pubkey: &PublicKey) -> Result<SignedMessage, ThresholdCryptoError> {
        match pubkey {
            PublicKey::BLS04(key) => {
                let shares = unwrap_enum_vec!(shares, SignatureShare::BLS04, ThresholdCryptoError::WrongScheme);

                if shares.is_ok() {
                    return Ok(SignedMessage::BLS04(Bls04ThresholdSignature::assemble(&shares.unwrap(), msg, key)));
                }

                Err(shares.err().unwrap())
            },
            _ => Err(ThresholdCryptoError::WrongKeyProvided)
        }
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

#[derive(Debug)]
pub enum ThresholdCryptoError {
    WrongGroup,
    WrongScheme,
    WrongKeyProvided,
    SerializationFailed,
    DeserializationFailed,
    CurveDoesNotSupportPairings,
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