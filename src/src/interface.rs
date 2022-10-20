use rasn::{der::{encode, decode}, Encode, Decode, Encoder, AsnType};
use crate::{rand::{RNG, RngAlgorithm}, dl_schemes::{ciphers::{sg02::*, bz03::{Bz03ThresholdCipher, Bz03Ciphertext, Bz03DecryptionShare}, sg02::Sg02Ciphertext}, signatures::{bls04::{Bls04SignatureShare, Bls04SignedMessage, Bls04ThresholdSignature}, frost::{FrostSignatureShare, FrostThresholdSignature}}, coins::cks05::{Cks05CoinShare, Cks05ThresholdCoin}}, keys::{PrivateKey, PublicKey}, unwrap_enum_vec, group::{GroupElement}, proto::scheme_types::{ThresholdScheme, Group}, rsa_schemes::signatures::sh00::{Sh00ThresholdSignature, Sh00SignedMessage, Sh00SignatureShare}};

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

pub trait DlShare {
    fn get_id(&self) -> u16;
    fn get_data(&self) -> GroupElement;
    fn get_group(&self) -> Group;
}

impl ThresholdScheme {
    pub fn get_id(&self) -> u8 {
        *self as u8
    }

    pub fn from_id(id: u8) -> ThresholdScheme {
        match id {
            0 => Self::Bz03,
            1 => Self::Sg02,
            2 => Self::Bls04,
            3 => Self::Cks05,
            4 => Self::Frost,
            5 => Self::Sh00,
            _ => panic!("unknown scheme id")
        }
    }
}



/* Threshold Coin */

#[derive(PartialEq, AsnType, Clone)]
#[rasn(enumerated)]
pub enum CoinShare {
    Cks05(Cks05CoinShare)
}

impl CoinShare {
    pub fn get_id(&self) -> u16 {
        match self {
            Self::Cks05(share) => share.get_id(),
            _ => todo!()
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            Self::Cks05(share) => share.get_group(),
            _ => todo!()
        }
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Self::Cks05(share) => share.get_scheme(),
            _ => todo!()
        }
    }

    pub fn get_data(&self) -> GroupElement {
        match self {
            Self::Cks05(share) => share.get_data(),
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

impl Decode for CoinShare {
    fn decode_with_tag<Dec: rasn::Decoder>(decoder: &mut Dec, tag: rasn::Tag) -> Result<Self, Dec::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let scheme = ThresholdScheme::from_id(u8::decode(sequence)?);
            let bytes = Vec::<u8>::decode(sequence)?;

            match scheme {
                ThresholdScheme::Cks05 => {
                    let key: Cks05CoinShare = decode(&bytes).unwrap();
                    Ok(CoinShare::Cks05(key))
                }, 
                _ => {
                    panic!("invalid scheme!");
                }
            }
        })
    }
}

impl Encode for CoinShare {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        match self  {
            Self::Cks05(share) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Cks05)).encode(sequence)?;
                    share.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
        }
    }
}

pub struct ThresholdCoin {}

impl ThresholdCoin {
    pub fn create_share(name: &[u8], private_key: &PrivateKey, rng: &mut RNG) -> Result<CoinShare, ThresholdCryptoError> {
        match private_key {
            PrivateKey::Cks05(sk) => {
                return Ok(CoinShare::Cks05(Cks05ThresholdCoin::create_share(name, sk, rng)));
            },
            _ => return Err(ThresholdCryptoError::WrongKeyProvided),
        }
    }

    pub fn verify_share(share: &CoinShare, name: &[u8],  public_key: &PublicKey) -> Result<bool, ThresholdCryptoError> {
        match public_key {
            PublicKey::Cks05(pk) => {
                match share {
                    CoinShare::Cks05(s) => {
                        return Ok(Cks05ThresholdCoin::verify_share(s, name, pk));
                    }
                }
                
            },
            _ => return Err(ThresholdCryptoError::WrongKeyProvided),
        }
    }

    pub fn assemble(shares: &Vec<CoinShare>) -> Result<u8, ThresholdCryptoError> {
        let share_vec = unwrap_enum_vec!(shares, CoinShare::Cks05, ThresholdCryptoError::WrongScheme);
        
        if share_vec.is_ok() {
            return Ok(Cks05ThresholdCoin::assemble(&share_vec.unwrap()));
        }

        Err(share_vec.err().unwrap())
    }
}


/* ---- NEW API ---- */

#[derive(PartialEq, AsnType, Clone)]
#[rasn(enumerated)]
pub enum Ciphertext {
    Sg02(Sg02Ciphertext),
    Bz03(Bz03Ciphertext)
}

impl Ciphertext {
    pub fn get_msg(&self) -> Vec<u8> {
        match self {
            Ciphertext::Sg02(ct) => ct.get_msg(),
            Ciphertext::Bz03(ct) => ct.get_msg(),
            _ => todo!()
        }
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Ciphertext::Sg02(_ct) => ThresholdScheme::Sg02,
            Ciphertext::Bz03(_ct) => ThresholdScheme::Bz03,
            _ => todo!()
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            Ciphertext::Sg02(ct) => ct.get_group(),
            Ciphertext::Bz03(ct) => ct.get_group(),
            _ => todo!()
        }
    }

    pub fn get_label(&self) -> Vec<u8> {
        match self {
            Ciphertext::Sg02(ct) => ct.get_label(),
            Ciphertext::Bz03(ct) => ct.get_label(),
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
            Self::Sg02(ct) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Sg02)).encode(sequence)?;
                    ct.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::Bz03(ct) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Bz03)).encode(sequence)?;
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
                ThresholdScheme::Sg02 => {
                    let key: Sg02Ciphertext = decode(&bytes).unwrap();
                    Ok(Ciphertext::Sg02(key))
                }, 
                ThresholdScheme::Bz03 => {
                    let key: Bz03Ciphertext = decode(&bytes).unwrap();
                    Ok(Ciphertext::Bz03(key))
                }, 
                _ => {
                    panic!("invalid scheme!");
                }
            }
        })
    }
}

pub struct ThresholdCipher {}

#[derive(PartialEq, AsnType, Clone)]
#[rasn(enumerated)]
pub enum DecryptionShare {
    Sg02(Sg02DecryptionShare),
    Bz03(Bz03DecryptionShare),
}

impl ThresholdCipher {
    pub fn encrypt(msg: &[u8], label: &[u8], pubkey: &PublicKey, params: &mut ThresholdCipherParams) -> Result<Ciphertext, ThresholdCryptoError> {
        match pubkey {
            PublicKey::Sg02(key) => {
                Ok(Ciphertext::Sg02(Sg02ThresholdCipher::encrypt(msg, label, key, params)))
            },
            PublicKey::Bz03(key) => {
                Ok(Ciphertext::Bz03(Bz03ThresholdCipher::encrypt(msg, label, key, params)))
            },
            _ => Err(ThresholdCryptoError::WrongKeyProvided)
        }
    }
    
    pub fn verify_ciphertext(ct: &Ciphertext, pubkey: &PublicKey) -> Result<bool, ThresholdCryptoError> {
        match ct {
            Ciphertext::Sg02(ct) => {
                match pubkey {
                    PublicKey::Sg02(key) => {
                        Ok(Sg02ThresholdCipher::verify_ciphertext(ct, key))
                    }, 
                    _ => {
                        Err(ThresholdCryptoError::WrongKeyProvided)
                    }
                }
            },

            Ciphertext::Bz03(ct) => {
                match pubkey {
                    PublicKey::Bz03(key) => {
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
            Ciphertext::Sg02(ct) => {

                match share {
                    DecryptionShare::Sg02(s) => {
                        match pubkey {
                            PublicKey::Sg02(key) => {
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

            Ciphertext::Bz03(ct) => {
                match share {
                    DecryptionShare::Bz03(s) => {
                        match pubkey {
                            PublicKey::Bz03(key) => {
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
            Ciphertext::Sg02(ct) => {
                match privkey {
                    PrivateKey::Sg02(key) => {
                        Ok(DecryptionShare::Sg02(Sg02ThresholdCipher::partial_decrypt(ct, key, params)))
                    }, 
                    _ => {
                        Err(ThresholdCryptoError::WrongKeyProvided)
                    }
                }
            },
            Ciphertext::Bz03(ct) => {
                match privkey {
                    PrivateKey::Bz03(key) => {
                        Ok(DecryptionShare::Bz03(Bz03ThresholdCipher::partial_decrypt(ct, key, params)))
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
            Ciphertext::Sg02(ct) => {
                let shares = unwrap_enum_vec!(shares, DecryptionShare::Sg02, ThresholdCryptoError::WrongScheme);

                if shares.is_ok() {
                    return Ok(Sg02ThresholdCipher::assemble(&shares.unwrap(), ct));
                }

                Err(shares.err().unwrap())
            },
            Ciphertext::Bz03(ct) => {
                let shares = unwrap_enum_vec!(shares, DecryptionShare::Bz03, ThresholdCryptoError::WrongScheme);

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
            Self::Sg02(share) => share.get_id(),
            _ => todo!()
        }
    }

    pub fn get_label(&self) -> Vec<u8> {
        match self {
            DecryptionShare::Sg02(share) => share.get_label(),
            _ => todo!()
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            Self::Sg02(share) => share.get_group(),
            _ => todo!()
        }
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Self::Sg02(share) => share.get_scheme(),
            _ => todo!()
        }
    }

    pub fn get_data(&self) -> GroupElement {
        match self {
            Self::Sg02(share) => share.get_data(),
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
                ThresholdScheme::Sg02 => {
                    let key: Sg02DecryptionShare = decode(&bytes).unwrap();
                    Ok(DecryptionShare::Sg02(key))
                }, 
                ThresholdScheme::Bz03 => {
                    let key: Bz03DecryptionShare = decode(&bytes).unwrap();
                    Ok(DecryptionShare::Bz03(key))
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
            Self::Sg02(share) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Sg02)).encode(sequence)?;
                    share.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::Bz03(share) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Bz03)).encode(sequence)?;
                    share.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            }
        }
    }
}


/* Threshold Signatures */

#[derive(PartialEq, AsnType, Clone)]
#[rasn(enumerated)]
pub enum SignatureShare {
    Bls04(Bls04SignatureShare),
    Sh00(Sh00SignatureShare)
}

impl SignatureShare {
    pub fn get_id(&self) -> u16 {
        match self {
            Self::Bls04(share) => share.get_id(),
            Self::Sh00(share) => share.get_id(),
            _ => todo!()
        }
    }

    pub fn get_label(&self) -> Vec<u8> {
        match self {
            Self::Bls04(share) => share.get_label(),
            Self::Sh00(share) => share.get_label(),
            _ => todo!()
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            Self::Bls04(share) => share.get_group(),
            Self::Sh00(share) => share.get_group(),
            _ => todo!()
        }
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Self::Bls04(share) => share.get_scheme(),
            Self::Sh00(share) => share.get_scheme(),
            _ => todo!()
        }
    }

    pub fn get_data(&self) -> GroupElement {
        match self {
            Self::Bls04(share) => share.get_data(),
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
                ThresholdScheme::Bls04 => {
                    let share: Bls04SignatureShare = decode(&bytes).unwrap();
                    Ok(SignatureShare::Bls04(share))
                }, 

                ThresholdScheme::Sh00 => {
                    let share: Sh00SignatureShare = decode(&bytes).unwrap();
                    Ok(SignatureShare::Sh00(share))
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
            Self::Bls04(share) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Bls04)).encode(sequence)?;
                    share.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },

            Self::Sh00(share) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Sh00)).encode(sequence)?;
                    share.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
        }
    }
}

#[derive(AsnType, PartialEq, Clone)]
#[rasn(enumerated)]
pub enum SignedMessage {
    Bls04(Bls04SignedMessage),
    Sh00(Sh00SignedMessage)
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
                ThresholdScheme::Bls04 => {
                    let share: Bls04SignedMessage = decode(&bytes).unwrap();
                    Ok(SignedMessage::Bls04(share))
                }, 

                ThresholdScheme::Sh00 => {
                    let share: Sh00SignedMessage = decode(&bytes).unwrap();
                    Ok(SignedMessage::Sh00(share))
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
            Self::Bls04(share) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Bls04)).encode(sequence)?;
                    share.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },

            Self::Sh00(share) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Sh00)).encode(sequence)?;
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
            SignedMessage::Bls04(s) => {
                match pubkey {
                    PublicKey::Bls04(key) => Bls04ThresholdSignature::verify(s, key),
                    _ => Result::Err(ThresholdCryptoError::WrongKeyProvided)
                }
            },

            SignedMessage::Sh00(s) => {
                match pubkey {
                    PublicKey::Sh00(key) => Ok(Sh00ThresholdSignature::verify(s, key)),
                    _ => Result::Err(ThresholdCryptoError::WrongKeyProvided)
                }
            }
        }
    }

    pub fn partial_sign(msg: &[u8], label: &[u8], secret: &PrivateKey, params: &mut ThresholdSignatureParams) -> Result<SignatureShare, ThresholdCryptoError>  {
        match secret {
            PrivateKey::Bls04(s) => {
                Result::Ok(SignatureShare::Bls04(Bls04ThresholdSignature::partial_sign(msg, label,s, params)))
            },
            PrivateKey::Sh00(s) => {
                Result::Ok(SignatureShare::Sh00(Sh00ThresholdSignature::partial_sign(msg, label,s, params)))
            },/* 
            PrivateKey::Frost(s) => {
                Result::Ok(SignatureShare::Frost(FrostThresholdSignature::partial_sign(s, msg, label,s, params)))
            },*/
            _ => Result::Err(ThresholdCryptoError::WrongKeyProvided)
        }
    }

    pub fn verify_share(share: &SignatureShare, msg: &[u8], pubkey: &PublicKey) -> Result<bool, ThresholdCryptoError>  {
        match share {
            SignatureShare::Bls04(s) => {
                match pubkey {
                    PublicKey::Bls04(key) => Bls04ThresholdSignature::verify_share(s, msg, key),
                _ => Result::Err(ThresholdCryptoError::WrongKeyProvided)
                }
            },

            SignatureShare::Sh00(s) => {
                match pubkey {
                    PublicKey::Sh00(key) => Ok(Sh00ThresholdSignature::verify_share(s, msg, key)),
                _ => Result::Err(ThresholdCryptoError::WrongKeyProvided)
                }
            }
        }
    }

    pub fn assemble(shares: &Vec<SignatureShare>, msg: &[u8], pubkey: &PublicKey) -> Result<SignedMessage, ThresholdCryptoError> {
        match pubkey {
            PublicKey::Bls04(key) => {
                let shares = unwrap_enum_vec!(shares, SignatureShare::Bls04, ThresholdCryptoError::WrongScheme);

                if shares.is_ok() {
                    return Ok(SignedMessage::Bls04(Bls04ThresholdSignature::assemble(&shares.unwrap(), msg, key)));
                }

                Err(shares.err().unwrap())
            },

            PublicKey::Sh00(key) => {
                let shares = unwrap_enum_vec!(shares, SignatureShare::Sh00, ThresholdCryptoError::WrongScheme);

                if shares.is_ok() {
                    return Ok(SignedMessage::Sh00(Sh00ThresholdSignature::assemble(&shares.unwrap(), msg, key)));
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

#[derive(Clone, Debug)]
pub enum ThresholdCryptoError {
    WrongGroup,
    WrongScheme,
    WrongKeyProvided,
    SerializationFailed,
    DeserializationFailed,
    CurveDoesNotSupportPairings,
    ParamsNotSet,
    IdNotFound,
    IncompatibleGroup,
    WrongState,
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