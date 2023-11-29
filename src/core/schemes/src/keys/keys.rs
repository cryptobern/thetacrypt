#![allow(non_snake_case)]

use asn1::ParseError;
use asn1::WriteError;
use base64::{engine::general_purpose, Engine as _};
use mcore::hash256::HASH256;
use rasn::AsnType;
use serde::ser::SerializeSeq;
use theta_proto::scheme_types::ThresholdOperation;

use crate::dl_schemes::ciphers::bz03::Bz03PrivateKey;
use crate::dl_schemes::ciphers::bz03::Bz03PublicKey;
use crate::dl_schemes::ciphers::sg02::Sg02PrivateKey;
use crate::dl_schemes::ciphers::sg02::Sg02PublicKey;
use crate::dl_schemes::coins::cks05::Cks05PrivateKey;
use crate::dl_schemes::coins::cks05::Cks05PublicKey;
use crate::dl_schemes::signatures::bls04::Bls04PrivateKey;
use crate::dl_schemes::signatures::bls04::Bls04PublicKey;
use crate::dl_schemes::signatures::frost::FrostPrivateKey;
use crate::dl_schemes::signatures::frost::FrostPublicKey;
use crate::interface::SchemeError;
use crate::interface::Serializable;
use crate::scheme_types_impl::SchemeDetails;
use theta_proto::scheme_types::Group;
use theta_proto::scheme_types::ThresholdScheme;

use crate::rsa_schemes::signatures::sh00::Sh00PrivateKey;
use crate::rsa_schemes::signatures::sh00::Sh00PublicKey;

#[derive(AsnType, Clone, Debug)]
#[rasn(enumerated)]
pub enum PrivateKeyShare {
    Sg02(Sg02PrivateKey),
    Bz03(Bz03PrivateKey),
    Bls04(Bls04PrivateKey),
    Cks05(Cks05PrivateKey),
    Sh00(Sh00PrivateKey),
    Frost(FrostPrivateKey),
}

impl Eq for PrivateKeyShare {}

impl PartialEq for PrivateKeyShare {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Sg02(l0), Self::Sg02(r0)) => l0.eq(r0),
            (Self::Bz03(l0), Self::Bz03(r0)) => l0.eq(r0),
            (Self::Bls04(l0), Self::Bls04(r0)) => l0.eq(r0),
            (Self::Sh00(l0), Self::Sh00(r0)) => l0.eq(r0),
            (Self::Frost(l0), Self::Frost(r0)) => l0.eq(r0),
            (Self::Cks05(l0), Self::Cks05(r0)) => l0.eq(r0),
            _ => false,
        }
    }
}

impl PrivateKeyShare {
    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Self::Sg02(_) => ThresholdScheme::Sg02,
            Self::Bz03(_) => ThresholdScheme::Bz03,
            Self::Bls04(_) => ThresholdScheme::Bls04,
            Self::Cks05(_) => ThresholdScheme::Cks05,
            Self::Sh00(_) => ThresholdScheme::Sh00,
            Self::Frost(_) => ThresholdScheme::Frost,
        }
    }

    pub fn get_key_id(&self) -> &str {
        match self {
            PrivateKeyShare::Sg02(key) => key.get_key_id(),
            PrivateKeyShare::Bz03(key) => key.get_key_id(),
            PrivateKeyShare::Bls04(key) => key.get_key_id(),
            PrivateKeyShare::Cks05(key) => key.get_key_id(),
            PrivateKeyShare::Sh00(key) => key.get_key_id(),
            PrivateKeyShare::Frost(key) => key.get_key_id(),
        }
    }

    pub fn get_share_id(&self) -> u16 {
        match self {
            PrivateKeyShare::Sg02(key) => key.get_share_id(),
            PrivateKeyShare::Bz03(key) => key.get_share_id(),
            PrivateKeyShare::Bls04(key) => key.get_share_id(),
            PrivateKeyShare::Cks05(key) => key.get_share_id(),
            PrivateKeyShare::Sh00(key) => key.get_share_id(),
            PrivateKeyShare::Frost(key) => key.get_share_id(),
        }
    }

    pub fn get_group(&self) -> &Group {
        match self {
            PrivateKeyShare::Sg02(key) => key.get_group(),
            PrivateKeyShare::Bz03(key) => key.get_group(),
            PrivateKeyShare::Bls04(key) => key.get_group(),
            PrivateKeyShare::Cks05(key) => key.get_group(),
            PrivateKeyShare::Sh00(key) => key.get_group(),
            PrivateKeyShare::Frost(key) => key.get_group(),
        }
    }

    pub fn get_threshold(&self) -> u16 {
        match self {
            PrivateKeyShare::Sg02(key) => key.get_threshold(),
            PrivateKeyShare::Bz03(key) => key.get_threshold(),
            PrivateKeyShare::Bls04(key) => key.get_threshold(),
            PrivateKeyShare::Cks05(key) => key.get_threshold(),
            PrivateKeyShare::Sh00(key) => key.get_threshold(),
            PrivateKeyShare::Frost(key) => key.get_threshold(),
        }
    }

    pub fn get_public_key(&self) -> PublicKey {
        match self {
            PrivateKeyShare::Sg02(key) => PublicKey::Sg02(key.get_public_key().clone()),
            PrivateKeyShare::Bz03(key) => PublicKey::Bz03(key.get_public_key().clone()),
            PrivateKeyShare::Bls04(key) => PublicKey::Bls04(key.get_public_key().clone()),
            PrivateKeyShare::Cks05(key) => PublicKey::Cks05(key.get_public_key().clone()),
            PrivateKeyShare::Sh00(key) => PublicKey::Sh00(key.get_public_key().clone()),
            PrivateKeyShare::Frost(key) => PublicKey::Frost(key.get_public_key().clone()),
        }
    }

    pub fn pem(&self) -> Result<String, SchemeError> {
        let r = self.to_bytes();
        if let Ok(bytes) = r {
            let encoded_url = general_purpose::URL_SAFE.encode(bytes);
            return Ok(encoded_url);
        }
        Err(r.unwrap_err())
    }

    pub fn from_pem(pem: &str) -> Result<Self, SchemeError> {
        let r = general_purpose::URL_SAFE.decode(pem);
        if let Ok(bytes) = r {
            return PrivateKeyShare::from_bytes(&bytes);
        }

        Err(SchemeError::DeserializationFailed)
    }
}

impl Serializable for PrivateKeyShare {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        match self {
            Self::Sg02(key) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Sg02.get_id())?;

                        let bytes = key.to_bytes();
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
            Self::Bz03(key) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Bz03.get_id())?;

                        let bytes = key.to_bytes();
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
            Self::Cks05(key) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Cks05.get_id())?;

                        let bytes = key.to_bytes();
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
            Self::Bls04(key) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Bls04.get_id())?;

                        let bytes = key.to_bytes();
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
            Self::Frost(key) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Frost.get_id())?;

                        let bytes = key.to_bytes();
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
            Self::Sh00(key) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Sh00.get_id())?;

                        let bytes = key.to_bytes();
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

                let key;
                match scheme.unwrap() {
                    ThresholdScheme::Sg02 => {
                        let r = Sg02PrivateKey::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        key = Ok(Self::Sg02(r.unwrap()));
                    }
                    ThresholdScheme::Bz03 => {
                        let r = Bz03PrivateKey::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        key = Ok(Self::Bz03(r.unwrap()));
                    }
                    ThresholdScheme::Cks05 => {
                        let r = Cks05PrivateKey::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        key = Ok(Self::Cks05(r.unwrap()));
                    }
                    ThresholdScheme::Bls04 => {
                        let r = Bls04PrivateKey::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        key = Ok(Self::Bls04(r.unwrap()));
                    }
                    ThresholdScheme::Frost => {
                        let r = FrostPrivateKey::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        key = Ok(Self::Frost(r.unwrap()));
                    }
                    ThresholdScheme::Sh00 => {
                        let r = Sh00PrivateKey::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        key = Ok(Self::Sh00(r.unwrap()));
                    }
                }

                return key;
            });
        });

        if result.is_err() {
            return Err(SchemeError::DeserializationFailed);
        }

        return Ok(result.unwrap());
    }
}

impl serde::Serialize for PrivateKeyShare {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match Serializable::to_bytes(self) {
            // Ok(key_bytes) => { serializer.serialize_bytes(&key_bytes) },
            Ok(key_bytes) => {
                let mut seq = serializer.serialize_seq(Some(key_bytes.len()))?;
                for element in key_bytes.iter() {
                    seq.serialize_element(element)?;
                }
                seq.end()
            }
            Err(err) => Err(serde::ser::Error::custom(format!(
                "Could not serialize PrivateKey. err: {:?}",
                err
            ))),
        }
    }
}

struct PrivateKeyVisitor;
impl<'de> serde::de::Visitor<'de> for PrivateKeyVisitor {
    type Value = PrivateKeyShare;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of bytes")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut key_vec = Vec::new();
        while let Ok(Some(next)) = seq.next_element() {
            key_vec.push(next);
        }
        let key = PrivateKeyShare::from_bytes(&key_vec); //TODO: fix
        Ok(key.unwrap())
    }
}

impl<'de> serde::Deserialize<'de> for PrivateKeyShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // deserializer.deserialize_bytes(BytesVisitor)
        deserializer.deserialize_seq(PrivateKeyVisitor)
    }
}

#[derive(AsnType, Clone, PartialEq, Debug)]
#[rasn(enumerated)]
pub enum PublicKey {
    Sg02(Sg02PublicKey),
    Bz03(Bz03PublicKey),
    Bls04(Bls04PublicKey),
    Cks05(Cks05PublicKey),
    Sh00(Sh00PublicKey),
    Frost(FrostPublicKey),
}

impl Eq for PublicKey {}

impl Serializable for PublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        match self {
            Self::Sg02(key) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Sg02.get_id())?;

                        let bytes = key.to_bytes();
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
            Self::Bz03(key) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Bz03.get_id())?;

                        let bytes = key.to_bytes();
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
            Self::Cks05(key) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Cks05.get_id())?;

                        let bytes = key.to_bytes();
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
            Self::Bls04(key) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Bls04.get_id())?;

                        let bytes = key.to_bytes();
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
            Self::Frost(key) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Frost.get_id())?;

                        let bytes = key.to_bytes();
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
            Self::Sh00(key) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::Sh00.get_id())?;

                        let bytes = key.to_bytes();
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

                let key;
                match scheme.unwrap() {
                    ThresholdScheme::Sg02 => {
                        let r = Sg02PublicKey::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        key = Ok(Self::Sg02(r.unwrap()));
                    }
                    ThresholdScheme::Bz03 => {
                        let r = Bz03PublicKey::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        key = Ok(Self::Bz03(r.unwrap()));
                    }
                    ThresholdScheme::Cks05 => {
                        let r = Cks05PublicKey::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        key = Ok(Self::Cks05(r.unwrap()));
                    }
                    ThresholdScheme::Bls04 => {
                        let r = Bls04PublicKey::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        key = Ok(Self::Bls04(r.unwrap()));
                    }
                    ThresholdScheme::Frost => {
                        let r = FrostPublicKey::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        key = Ok(Self::Frost(r.unwrap()));
                    }
                    ThresholdScheme::Sh00 => {
                        let r = Sh00PublicKey::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        key = Ok(Self::Sh00(r.unwrap()));
                    }
                }

                return key;
            });
        });

        if result.is_err() {
            return Err(SchemeError::DeserializationFailed);
        }

        return Ok(result.unwrap());
    }
}

impl PublicKey {
    pub fn get_key_id(&self) -> &str {
        match self {
            PublicKey::Sg02(key) => key.get_key_id(),
            PublicKey::Bz03(key) => key.get_key_id(),
            PublicKey::Bls04(key) => key.get_key_id(),
            PublicKey::Sh00(key) => key.get_key_id(),
            PublicKey::Frost(key) => key.get_key_id(),
            PublicKey::Cks05(key) => key.get_key_id(),
        }
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            PublicKey::Sg02(_key) => ThresholdScheme::Sg02,
            PublicKey::Bz03(_key) => ThresholdScheme::Bz03,
            PublicKey::Bls04(_key) => ThresholdScheme::Bls04,
            PublicKey::Cks05(_key) => ThresholdScheme::Cks05,
            PublicKey::Sh00(_key) => ThresholdScheme::Sh00,
            PublicKey::Frost(_key) => ThresholdScheme::Frost,
        }
    }

    pub fn get_operation(&self) -> ThresholdOperation {
        self.get_scheme().get_operation()
    }

    pub fn get_group(&self) -> &Group {
        match self {
            PublicKey::Sg02(key) => key.get_group(),
            PublicKey::Bz03(key) => key.get_group(),
            PublicKey::Bls04(key) => key.get_group(),
            PublicKey::Cks05(key) => key.get_group(),
            PublicKey::Sh00(key) => key.get_group(),
            PublicKey::Frost(key) => key.get_group(),
        }
    }

    pub fn get_threshold(&self) -> u16 {
        match self {
            PublicKey::Sg02(key) => key.get_threshold(),
            PublicKey::Bz03(key) => key.get_threshold(),
            PublicKey::Bls04(key) => key.get_threshold(),
            PublicKey::Cks05(key) => key.get_threshold(),
            PublicKey::Sh00(key) => key.get_threshold(),
            PublicKey::Frost(key) => key.get_threshold(),
        }
    }

    pub fn get_n(&self) -> u16 {
        match self {
            PublicKey::Sg02(key) => key.get_n(),
            PublicKey::Bz03(key) => key.get_n(),
            PublicKey::Bls04(key) => key.get_n(),
            PublicKey::Cks05(key) => key.get_n(),
            PublicKey::Sh00(key) => key.get_n(),
            PublicKey::Frost(key) => key.get_n(),
        }
    }

    pub fn pem(&self) -> Result<String, SchemeError> {
        let r = self.to_bytes();
        if let Ok(bytes) = r {
            let encoded_url = general_purpose::URL_SAFE.encode(bytes);
            return Ok(encoded_url);
        }
        Err(r.unwrap_err())
    }

    pub fn from_pem(pem: &str) -> Result<Self, SchemeError> {
        let r = general_purpose::URL_SAFE.decode(pem);
        if let Ok(bytes) = r {
            return PublicKey::from_bytes(&bytes);
        }

        Err(SchemeError::DeserializationFailed)
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // deserializer.deserialize_bytes(BytesVisitor)
        deserializer.deserialize_seq(PublicKeyVisitor)
    }
}

impl serde::Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match Serializable::to_bytes(self) {
            // Ok(key_bytes) => { serializer.serialize_bytes(&key_bytes) },
            Ok(key_bytes) => {
                let mut seq = serializer.serialize_seq(Some(key_bytes.len()))?;
                for element in key_bytes.iter() {
                    seq.serialize_element(element)?;
                }
                seq.end()
            }
            Err(err) => Err(serde::ser::Error::custom(format!(
                "Could not serialize PublicKey. err: {:?}",
                err
            ))),
        }
    }
}

struct PublicKeyVisitor;
impl<'de> serde::de::Visitor<'de> for PublicKeyVisitor {
    type Value = PublicKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of bytes")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut key_vec = Vec::new();
        while let Ok(Some(next)) = seq.next_element() {
            key_vec.push(next);
        }
        let key = PublicKey::from_bytes(&key_vec); //TODO: fix
        Ok(key.unwrap())
    }
}

pub fn calc_key_id(bytes: &[u8]) -> String {
    let mut hash = HASH256::new();
    hash.process_array(&bytes);
    general_purpose::URL_SAFE.encode(hash.hash())
}

pub fn key2id(key: &PublicKey) -> String {
    let bytes = key.to_bytes().unwrap();
    let inner_bytes: Result<Vec<u8>, ParseError> = asn1::parse(&bytes, |d| {
        return d.read_element::<asn1::Sequence>()?.parse(|d| {
            d.read_element::<u8>()?;
            let bytes = d.read_element::<&[u8]>()?.to_vec();

            return Ok(bytes);
        });
    });

    calc_key_id(&inner_bytes.unwrap())
}
