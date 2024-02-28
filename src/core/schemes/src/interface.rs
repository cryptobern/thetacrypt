use std::fmt::write;
use std::{error::Error, fmt::Display};

use crate::dl_schemes::signatures::frost::FrostOptions;
use crate::keys::keys::{PrivateKeyShare, PublicKey};
use crate::scheme_types_impl::SchemeDetails;
use crate::{
    dl_schemes::{
        ciphers::{
            bz03::{Bz03Ciphertext, Bz03DecryptionShare, Bz03ThresholdCipher},
            sg02::Sg02Ciphertext,
            sg02::*,
        },
        coins::cks05::{Cks05CoinShare, Cks05ThresholdCoin},
        signatures::{
            bls04::{Bls04Signature, Bls04SignatureShare, Bls04ThresholdSignature},
            frost::{FrostSignature, FrostSignatureShare},
        },
    },
    groups::group::GroupElement,
    rand::{RngAlgorithm, RNG},
    rsa_schemes::signatures::sh00::{Sh00Signature, Sh00SignatureShare, Sh00ThresholdSignature},
    unwrap_enum_vec,
};
use asn1::{ParseError, WriteError};
use rasn::AsnType;
pub use theta_proto::scheme_types::{Group, ThresholdScheme};

pub trait Serializable: Sized + Clone + PartialEq {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError>;
    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError>;
}

pub trait DlShare {
    fn get_id(&self) -> u16;
    fn get_data(&self) -> &GroupElement;
    fn get_group(&self) -> &Group;
}

/* Threshold Coin */

#[derive(PartialEq, AsnType, Clone)]
#[rasn(enumerated)]
pub enum CoinShare {
    Cks05(Cks05CoinShare),
}

impl CoinShare {
    pub fn get_id(&self) -> u16 {
        match self {
            Self::Cks05(share) => share.get_id(),
        }
    }

    pub fn get_group(&self) -> &Group {
        match self {
            Self::Cks05(share) => share.get_group(),
        }
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Self::Cks05(share) => share.get_scheme(),
        }
    }

    pub fn get_data(&self) -> &GroupElement {
        match self {
            Self::Cks05(share) => share.get_data(),
        }
    }
}

impl Serializable for CoinShare {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        match self {
            Self::Cks05(share) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Cks05.get_id())?;

                        let bytes = share.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }
                        w.write_element(&bytes.unwrap().as_slice())?;
                        Ok(())
                    }))
                });

                if result.is_err() {
                    return Err(SchemeError::SerializationFailed);
                }

                return Ok(result.unwrap());
            }
        }
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let scheme = ThresholdScheme::from_i32(d.read_element::<u8>()? as i32);
                let bytes = d.read_element::<&[u8]>()?.to_vec();

                if scheme.is_none() {
                    return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                }

                let share;
                match scheme.unwrap() {
                    ThresholdScheme::Cks05 => {
                        let r = Cks05CoinShare::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        share = Ok(CoinShare::Cks05(r.unwrap()));
                    }
                    _ => {
                        return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                    }
                }

                return share;
            });
        });

        if result.is_err() {
            return Err(SchemeError::DeserializationFailed);
        }

        return Ok(result.unwrap());
    }
}

pub struct ThresholdCoin {}

impl ThresholdCoin {
    pub fn create_share(
        name: &[u8],
        private_key: &PrivateKeyShare,
        rng: &mut RNG,
    ) -> Result<CoinShare, SchemeError> {
        match private_key {
            PrivateKeyShare::Cks05(sk) => {
                return Ok(CoinShare::Cks05(Cks05ThresholdCoin::create_share(
                    name, sk, rng,
                )));
            }
            _ => return Err(SchemeError::WrongKeyProvided),
        }
    }

    pub fn verify_share(
        share: &CoinShare,
        name: &[u8],
        public_key: &PublicKey,
    ) -> Result<bool, SchemeError> {
        match public_key {
            PublicKey::Cks05(pk) => match share {
                CoinShare::Cks05(s) => {
                    return Ok(Cks05ThresholdCoin::verify_share(s, name, pk));
                }
            },
            _ => return Err(SchemeError::WrongKeyProvided),
        }
    }

    pub fn assemble(shares: &Vec<CoinShare>) -> Result<u8, SchemeError> {
        let share_vec = unwrap_enum_vec!(shares, CoinShare::Cks05, SchemeError::WrongScheme);

        if share_vec.is_ok() {
            return Ok(Cks05ThresholdCoin::assemble(&share_vec.unwrap()));
        }

        Err(share_vec.err().unwrap())
    }
}

/* ---- NEW API ---- */

#[derive(PartialEq, AsnType, Clone, Debug)]
#[rasn(enumerated)]
pub enum Ciphertext {
    Sg02(Sg02Ciphertext),
    Bz03(Bz03Ciphertext),
}

impl Ciphertext {
    pub fn get_ctxt(&self) -> &[u8] {
        match self {
            Ciphertext::Sg02(ct) => ct.get_ctxt(),
            Ciphertext::Bz03(ct) => ct.get_ctxt(),
        }
    }

    pub fn get_ck(&self) -> &[u8] {
        match self {
            Ciphertext::Sg02(ct) => ct.get_ck(),
            Ciphertext::Bz03(ct) => ct.get_ck(),
        }
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Ciphertext::Sg02(_ct) => ThresholdScheme::Sg02,
            Ciphertext::Bz03(_ct) => ThresholdScheme::Bz03,
        }
    }

    pub fn get_group(&self) -> &Group {
        match self {
            Ciphertext::Sg02(ct) => ct.get_group(),
            Ciphertext::Bz03(ct) => ct.get_group(),
        }
    }

    pub fn get_label(&self) -> &[u8] {
        match self {
            Ciphertext::Sg02(ct) => ct.get_label(),
            Ciphertext::Bz03(ct) => ct.get_label(),
        }
    }

    pub fn get_key_id(&self) -> &str {
        match self {
            Ciphertext::Sg02(ct) => ct.get_key_id(),
            Ciphertext::Bz03(ct) => ct.get_key_id(),
        }
    }
}

impl Serializable for Ciphertext {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        match self {
            Self::Sg02(ct) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Sg02.get_id())?;

                        let bytes = ct.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }
                        w.write_element(&bytes.unwrap().as_slice())?;
                        Ok(())
                    }))
                });

                if result.is_err() {
                    return Err(SchemeError::SerializationFailed);
                }

                return Ok(result.unwrap());
            }
            Self::Bz03(ct) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Bz03.get_id())?;
                        let bytes = ct.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }
                        w.write_element(&bytes.unwrap().as_slice())?;
                        Ok(())
                    }))
                });

                if result.is_err() {
                    return Err(SchemeError::SerializationFailed);
                }

                return Ok(result.unwrap());
            }
        }
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let scheme = ThresholdScheme::from_id(d.read_element::<u8>()?);
                let bytes = d.read_element::<&[u8]>()?.to_vec();

                if scheme.is_none() {
                    return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                }

                let ct;
                match scheme.unwrap() {
                    ThresholdScheme::Sg02 => {
                        let r = Sg02Ciphertext::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        ct = Ok(Ciphertext::Sg02(r.unwrap()));
                    }

                    ThresholdScheme::Bz03 => {
                        let r = Bz03Ciphertext::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        ct = Ok(Ciphertext::Bz03(r.unwrap()));
                    }
                    _ => {
                        return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                    }
                }

                return ct;
            });
        });

        if result.is_err() {
            return Err(SchemeError::DeserializationFailed);
        }

        return Ok(result.unwrap());
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
    pub fn encrypt(
        msg: &[u8],
        label: &[u8],
        pubkey: &PublicKey,
        params: &mut ThresholdCipherParams,
    ) -> Result<Ciphertext, SchemeError> {
        match pubkey {
            PublicKey::Sg02(key) => Ok(Ciphertext::Sg02(Sg02ThresholdCipher::encrypt(
                msg, label, key, params,
            ))),
            PublicKey::Bz03(key) => Ok(Ciphertext::Bz03(Bz03ThresholdCipher::encrypt(
                msg, label, key, params,
            ))),
            _ => Err(SchemeError::WrongKeyProvided),
        }
    }

    pub fn verify_ciphertext(ct: &Ciphertext, pubkey: &PublicKey) -> Result<bool, SchemeError> {
        match ct {
            Ciphertext::Sg02(ct) => match pubkey {
                PublicKey::Sg02(key) => Ok(Sg02ThresholdCipher::verify_ciphertext(ct, key)),
                _ => Err(SchemeError::WrongKeyProvided),
            },

            Ciphertext::Bz03(ct) => match pubkey {
                PublicKey::Bz03(key) => Bz03ThresholdCipher::verify_ciphertext(ct, key),
                _ => Err(SchemeError::WrongKeyProvided),
            },
        }
    }

    pub fn verify_share(
        share: &DecryptionShare,
        ct: &Ciphertext,
        pubkey: &PublicKey,
    ) -> Result<bool, SchemeError> {
        match ct {
            Ciphertext::Sg02(ct) => match share {
                DecryptionShare::Sg02(s) => match pubkey {
                    PublicKey::Sg02(key) => Ok(Sg02ThresholdCipher::verify_share(s, ct, key)),
                    _ => Err(SchemeError::WrongKeyProvided),
                },
                _ => Err(SchemeError::WrongScheme),
            },

            Ciphertext::Bz03(ct) => match share {
                DecryptionShare::Bz03(s) => match pubkey {
                    PublicKey::Bz03(key) => Bz03ThresholdCipher::verify_share(s, ct, key),
                    _ => Err(SchemeError::WrongKeyProvided),
                },
                _ => Err(SchemeError::WrongScheme),
            },
        }
    }

    pub fn partial_decrypt(
        ct: &Ciphertext,
        privkey: &PrivateKeyShare,
        params: &mut ThresholdCipherParams,
    ) -> Result<DecryptionShare, SchemeError> {
        match ct {
            Ciphertext::Sg02(ct) => match privkey {
                PrivateKeyShare::Sg02(key) => Ok(DecryptionShare::Sg02(
                    Sg02ThresholdCipher::partial_decrypt(ct, key, params),
                )),
                _ => Err(SchemeError::WrongKeyProvided),
            },
            Ciphertext::Bz03(ct) => match privkey {
                PrivateKeyShare::Bz03(key) => Ok(DecryptionShare::Bz03(
                    Bz03ThresholdCipher::partial_decrypt(ct, key, params),
                )),
                _ => Err(SchemeError::WrongKeyProvided),
            },
        }
    }

    pub fn assemble(
        shares: &Vec<DecryptionShare>,
        ct: &Ciphertext,
    ) -> Result<Vec<u8>, SchemeError> {
        match ct {
            Ciphertext::Sg02(ct) => {
                let shares =
                    unwrap_enum_vec!(shares, DecryptionShare::Sg02, SchemeError::WrongScheme);

                if shares.is_ok() {
                    return Sg02ThresholdCipher::assemble(&shares.unwrap(), ct);
                }

                Err(shares.err().unwrap())
            }
            Ciphertext::Bz03(ct) => {
                let shares =
                    unwrap_enum_vec!(shares, DecryptionShare::Bz03, SchemeError::WrongScheme);

                if shares.is_ok() {
                    return Bz03ThresholdCipher::assemble(&shares.unwrap(), ct);
                }

                Err(shares.err().unwrap())
            }
        }
    }
}

impl DecryptionShare {
    pub fn get_id(&self) -> u16 {
        match self {
            Self::Sg02(share) => share.get_id(),
            Self::Bz03(share) => share.get_id(),
        }
    }

    pub fn get_label(&self) -> &[u8] {
        match self {
            DecryptionShare::Sg02(share) => share.get_label(),
            DecryptionShare::Bz03(share) => share.get_label(),
        }
    }

    pub fn get_group(&self) -> &Group {
        match self {
            Self::Sg02(share) => share.get_group(),
            Self::Bz03(share) => share.get_group(),
        }
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Self::Sg02(share) => share.get_scheme(),
            Self::Bz03(share) => share.get_scheme(),
        }
    }

    pub fn get_data(&self) -> &GroupElement {
        match self {
            Self::Sg02(share) => share.get_data(),
            Self::Bz03(share) => share.get_data(),
        }
    }
}

impl Serializable for DecryptionShare {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        match self {
            Self::Sg02(share) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Sg02.get_id())?;

                        let bytes = share.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }
                        w.write_element(&bytes.unwrap().as_slice())?;
                        Ok(())
                    }))
                });

                if result.is_err() {
                    return Err(SchemeError::SerializationFailed);
                }

                return Ok(result.unwrap());
            }
            Self::Bz03(share) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Bz03.get_id())?;
                        let bytes = share.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }
                        w.write_element(&bytes.unwrap().as_slice())?;
                        Ok(())
                    }))
                });

                if result.is_err() {
                    return Err(SchemeError::SerializationFailed);
                }

                return Ok(result.unwrap());
            }
        }
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let scheme = ThresholdScheme::from_id(d.read_element::<u8>()?);
                let bytes = d.read_element::<&[u8]>()?.to_vec();

                if scheme.is_none() {
                    return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                }

                let share;
                match scheme.unwrap() {
                    ThresholdScheme::Sg02 => {
                        let r = Sg02DecryptionShare::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        share = Ok(DecryptionShare::Sg02(r.unwrap()));
                    }

                    ThresholdScheme::Bz03 => {
                        let r = Bz03DecryptionShare::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        share = Ok(DecryptionShare::Bz03(r.unwrap()));
                    }
                    _ => {
                        return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                    }
                }

                return share;
            });
        });

        if result.is_err() {
            return Err(SchemeError::DeserializationFailed);
        }

        return Ok(result.unwrap());
    }
}

/* Threshold Signatures */

#[derive(PartialEq, AsnType, Clone)]
#[rasn(enumerated)]
pub enum SignatureShare {
    Bls04(Bls04SignatureShare),
    Sh00(Sh00SignatureShare),
    Frost(FrostSignatureShare),
}

impl SignatureShare {
    pub fn get_id(&self) -> u16 {
        match self {
            Self::Bls04(share) => share.get_id(),
            Self::Sh00(share) => share.get_id(),
            Self::Frost(share) => share.get_id(),
        }
    }

    pub fn get_label(&self) -> &[u8] {
        match self {
            Self::Bls04(share) => share.get_label(),
            Self::Sh00(share) => share.get_label(),
            Self::Frost(share) => share.get_label(), // panics
        }
    }

    pub fn get_group(&self) -> &Group {
        match self {
            Self::Bls04(share) => share.get_group(),
            Self::Sh00(share) => share.get_group(),
            Self::Frost(share) => share.get_group(),
        }
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Self::Bls04(share) => share.get_scheme(),
            Self::Sh00(share) => share.get_scheme(),
            Self::Frost(share) => share.get_scheme(),
        }
    }

    pub fn get_data(&self) -> &GroupElement {
        match self {
            Self::Bls04(share) => share.get_data(),
            Self::Frost(share) => share.get_data(), // panics
            _ => todo!("not implemented"),
        }
    }
}

impl Serializable for SignatureShare {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        match self {
            Self::Bls04(share) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Bls04.get_id())?;

                        let bytes = share.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }
                        w.write_element(&bytes.unwrap().as_slice())?;
                        Ok(())
                    }))
                });

                if result.is_err() {
                    return Err(SchemeError::SerializationFailed);
                }

                return Ok(result.unwrap());
            }
            Self::Frost(share) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Frost.get_id())?;
                        let bytes = share.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }
                        w.write_element(&bytes.unwrap().as_slice())?;
                        Ok(())
                    }))
                });

                if result.is_err() {
                    return Err(SchemeError::SerializationFailed);
                }

                return Ok(result.unwrap());
            }
            Self::Sh00(share) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Sh00.get_id())?;
                        let bytes = share.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }
                        w.write_element(&bytes.unwrap().as_slice())?;
                        Ok(())
                    }))
                });

                if result.is_err() {
                    return Err(SchemeError::SerializationFailed);
                }

                return Ok(result.unwrap());
            }
        }
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let scheme = ThresholdScheme::from_id(d.read_element::<u8>()?);
                let bytes = d.read_element::<&[u8]>()?.to_vec();

                if scheme.is_none() {
                    return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                }

                let share;
                match scheme.unwrap() {
                    ThresholdScheme::Bls04 => {
                        let r = Bls04SignatureShare::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        share = Ok(SignatureShare::Bls04(r.unwrap()));
                    }

                    ThresholdScheme::Frost => {
                        let r = FrostSignatureShare::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        share = Ok(SignatureShare::Frost(r.unwrap()));
                    }

                    ThresholdScheme::Sh00 => {
                        let r = Sh00SignatureShare::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        share = Ok(SignatureShare::Sh00(r.unwrap()));
                    }
                    _ => {
                        return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                    }
                }

                return share;
            });
        });

        if result.is_err() {
            return Err(SchemeError::DeserializationFailed);
        }

        return Ok(result.unwrap());
    }
}

#[derive(AsnType, PartialEq, Clone, Debug)]
#[rasn(enumerated)]
pub enum Signature {
    Bls04(Bls04Signature),
    Sh00(Sh00Signature),
    Frost(FrostSignature),
}

impl Serializable for Signature {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        match self {
            Self::Bls04(sig) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Bls04.get_id())?;

                        let bytes = sig.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }
                        w.write_element(&bytes.unwrap().as_slice())?;
                        Ok(())
                    }))
                });

                if result.is_err() {
                    return Err(SchemeError::SerializationFailed);
                }

                return Ok(result.unwrap());
            }
            Self::Frost(sig) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Frost.get_id())?;
                        let bytes = sig.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }
                        w.write_element(&bytes.unwrap().as_slice())?;
                        Ok(())
                    }))
                });

                if result.is_err() {
                    return Err(SchemeError::SerializationFailed);
                }

                return Ok(result.unwrap());
            }
            Self::Sh00(sig) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Sh00.get_id())?;
                        let bytes = sig.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }
                        w.write_element(&bytes.unwrap().as_slice())?;
                        Ok(())
                    }))
                });

                if result.is_err() {
                    return Err(SchemeError::SerializationFailed);
                }

                return Ok(result.unwrap());
            }
        }
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let scheme = ThresholdScheme::from_id(d.read_element::<u8>()?);
                let bytes = d.read_element::<&[u8]>()?.to_vec();

                if scheme.is_none() {
                    return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                }

                let sig;
                match scheme.unwrap() {
                    ThresholdScheme::Bls04 => {
                        let r = Bls04Signature::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        sig = Ok(Signature::Bls04(r.unwrap()));
                    }

                    ThresholdScheme::Frost => {
                        let r = FrostSignature::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        sig = Ok(Signature::Frost(r.unwrap()));
                    }

                    ThresholdScheme::Sh00 => {
                        let r = Sh00Signature::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        sig = Ok(Signature::Sh00(r.unwrap()));
                    }
                    _ => {
                        return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                    }
                }

                return sig;
            });
        });

        if result.is_err() {
            return Err(SchemeError::DeserializationFailed);
        }

        return Ok(result.unwrap());
    }
}

#[derive(Debug)]
pub struct ThresholdSignature {}

impl ThresholdSignature {
    pub fn verify(sig: &Signature, pubkey: &PublicKey, msg: &[u8]) -> Result<bool, SchemeError> {
        match sig {
            Signature::Bls04(s) => match pubkey {
                PublicKey::Bls04(key) => Bls04ThresholdSignature::verify(s, key, msg),
                _ => Result::Err(SchemeError::WrongKeyProvided),
            },

            Signature::Sh00(s) => match pubkey {
                PublicKey::Sh00(key) => Ok(Sh00ThresholdSignature::verify(s, key, msg)),
                _ => Result::Err(SchemeError::WrongKeyProvided),
            },

            Signature::Frost(s) => match pubkey {
                PublicKey::Frost(key) => {
                    Ok(crate::dl_schemes::signatures::frost::verify(s, key, msg))
                }
                _ => Result::Err(SchemeError::WrongKeyProvided),
            },
            _ => Err(SchemeError::WrongKeyProvided),
        }
    }

    pub fn partial_sign(
        msg: &[u8],
        label: &[u8],
        secret: &PrivateKeyShare,
        params: &mut ThresholdSignatureParams,
    ) -> Result<SignatureShare, SchemeError> {
        match secret {
            PrivateKeyShare::Bls04(s) => Result::Ok(SignatureShare::Bls04(
                Bls04ThresholdSignature::partial_sign(msg, label, s, params),
            )),
            PrivateKeyShare::Sh00(s) => Result::Ok(SignatureShare::Sh00(
                Sh00ThresholdSignature::partial_sign(msg, label, s, params),
            )),
            _ => Result::Err(SchemeError::WrongKeyProvided),
        }
    }

    pub fn verify_share(
        share: &SignatureShare,
        msg: &[u8],
        pubkey: &PublicKey,
    ) -> Result<bool, SchemeError> {
        match share {
            SignatureShare::Bls04(s) => match pubkey {
                PublicKey::Bls04(key) => Bls04ThresholdSignature::verify_share(s, msg, key),
                _ => Result::Err(SchemeError::WrongKeyProvided),
            },

            SignatureShare::Sh00(s) => match pubkey {
                PublicKey::Sh00(key) => Ok(Sh00ThresholdSignature::verify_share(s, msg, key)),
                _ => Result::Err(SchemeError::WrongKeyProvided),
            },
            _ => return Err(SchemeError::WrongScheme),
        }
    }

    pub fn assemble(
        shares: &Vec<SignatureShare>,
        msg: &[u8],
        pubkey: &PublicKey,
    ) -> Result<Signature, SchemeError> {
        match pubkey {
            PublicKey::Bls04(key) => {
                let shares =
                    unwrap_enum_vec!(shares, SignatureShare::Bls04, SchemeError::WrongScheme);

                if shares.is_ok() {
                    return Ok(Signature::Bls04(Bls04ThresholdSignature::assemble(
                        &shares.unwrap(),
                        msg,
                        key,
                    )));
                }

                Err(shares.err().unwrap())
            }

            PublicKey::Sh00(key) => {
                let shares =
                    unwrap_enum_vec!(shares, SignatureShare::Sh00, SchemeError::WrongScheme);

                if shares.is_ok() {
                    return Ok(Signature::Sh00(Sh00ThresholdSignature::assemble(
                        &shares.unwrap(),
                        msg,
                        key,
                    )));
                }

                Err(shares.err().unwrap())
            }
            _ => Err(SchemeError::WrongKeyProvided),
        }
    }
}

pub enum ThresholdSignatureOptions {
    Frost(FrostOptions),
}

pub struct ThresholdSignatureParams {
    pub rng: RNG,
}

impl ThresholdSignatureParams {
    pub fn new() -> Self {
        let rng = RNG::new(crate::rand::RngAlgorithm::OsRng);
        Self { rng }
    }

    pub fn set_rng(&mut self, alg: RngAlgorithm) {
        self.rng = RNG::new(alg);
    }
}

#[derive(Clone, Debug)]
pub enum SchemeError {
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
    PreviousRoundNotExecuted,
    InvalidRound,
    InvalidShare,
    ProtocolNotFinished,
    NotReadyForNextRound,
    MessageNotSpecified,
    MessageAlreadySpecified,
    SerializationError(String),
    UnknownScheme,
    UnknownGroupString,
    UnknownGroup,
    IOError,
    InvalidParams(Option<String>),
    Aborted(String),
    KeyNotFound,
    MacFailure,
    NoMoreCommitments,
}

impl Error for SchemeError {}

impl Display for SchemeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongGroup => write!(f, "Wrong group"),
            Self::WrongScheme => write!(f, "Wrong scheme"),
            Self::WrongKeyProvided => write!(f, "Wrong key provided"),
            Self::SerializationFailed => write!(f, "Serialization failed"),
            Self::DeserializationFailed => write!(f, "Deseialization failed"),
            Self::CurveDoesNotSupportPairings => write!(f, "Curve does not support pairings"),
            Self::ParamsNotSet => write!(f, "Parameters not set"),
            Self::IdNotFound => write!(f, "ID not found"),
            Self::IncompatibleGroup => write!(f, "Incompatible group"),
            Self::WrongState => write!(f, "Wrong state"),
            Self::PreviousRoundNotExecuted => write!(f, "Previous round not executed"),
            Self::InvalidRound => write!(f, "Invalid round"),
            Self::InvalidShare => write!(f, "Invalid share"),
            Self::ProtocolNotFinished => write!(f, "Protocol not finished"),
            Self::NotReadyForNextRound => write!(f, "Not ready for next round"),
            Self::MessageNotSpecified => write!(f, "Message not specified"),
            Self::MessageAlreadySpecified => write!(f, "Message already specified"),
            Self::SerializationError(s) => write!(f, "Serialization error: {}", s),
            Self::UnknownScheme => write!(f, "Unknown scheme"),
            Self::UnknownGroupString => write!(f, "Unknown group string"),
            Self::UnknownGroup => write!(f, "Unknown group"),
            Self::IOError => write!(f, "I/O error"),
            Self::InvalidParams(details) => match details {
                Some(s) => write!(f, "Invalid parameters: {}", s),
                None => write!(f, "Invalid parameters"),
            },
            Self::Aborted(s) => write!(f, "Protocol aborted: {}", s),
            Self::MacFailure => write!(f, "MAC Failure"),
            Self::KeyNotFound => write!(f, "Key not found"),
            Self::NoMoreCommitments => write!(f, "No more commitments available"),
        }
    }
}

pub struct ThresholdCipherParams {
    pub rng: RNG,
}

impl ThresholdCipherParams {
    pub fn new() -> Self {
        let rng = RNG::new(crate::rand::RngAlgorithm::OsRng);
        Self { rng }
    }

    pub fn set_rng(&mut self, alg: RngAlgorithm) {
        self.rng = RNG::new(alg);
    }
}
