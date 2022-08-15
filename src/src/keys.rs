use std::convert::TryInto;

use derive::Serializable;
use rasn::AsnType;
use rasn::Decode;
use rasn::Encode;
use rasn::Encoder;
use rasn::ber::encode;
use rasn::der::decode;

use crate::dl_schemes::bigint::BigImpl;
use crate::dl_schemes::ciphers::bz03::Bz03PrivateKey;
use crate::dl_schemes::ciphers::bz03::Bz03PublicKey;
use crate::dl_schemes::ciphers::sg02::Sg02PrivateKey;
use crate::dl_schemes::ciphers::sg02::Sg02PublicKey;
use crate::dl_schemes::common::shamir_share;
use crate::dl_schemes::signatures::bls04::Bls04PrivateKey;
use crate::dl_schemes::signatures::bls04::Bls04PublicKey;
use crate::group::GroupElement;
use crate::group::Group;
use crate::interface::Serializable;
use crate::interface::ThresholdCryptoError;
use crate::interface::ThresholdScheme;
use crate::rand::RNG;

#[macro_export]
macro_rules! unwrap_enum_vec {
    ($vec:expr, $variant:path, $err:expr) => {
        {
        let mut vec = Vec::new();
        for i in 0..$vec.len() {
            let val = &$vec[i];
            match val {
                $variant(x) => {
                    vec.push((*x).clone());
                },
                _ => Err($err)?,
            }
        }
        Ok(vec)
        }
    };
}

#[derive(AsnType, Clone)]
#[rasn(enumerated)]
pub enum PrivateKey {
    SG02(Sg02PrivateKey),
    BZ03(Bz03PrivateKey),
    BLS04(Bls04PrivateKey)
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::SG02(l0), Self::SG02(r0)) => l0.eq(r0),
            (Self::BZ03(l0), Self::BZ03(r0)) => l0.eq(r0),
            (Self::BLS04(l0), Self::BLS04(r0)) => l0.eq(r0),
            _ => false
        }
    }
}

impl PrivateKey {
    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Self::SG02(_) => ThresholdScheme::SG02,
            Self::BZ03(_) => ThresholdScheme::BZ03,
            Self::BLS04(_) => ThresholdScheme::BLS04,
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            PrivateKey::SG02(key) => key.get_group(),
            PrivateKey::BZ03(key) => key.get_group(),
            PrivateKey::BLS04(key) => key.get_group()
        }
    }

    pub fn get_threshold(&self) -> u16 {
        match self {
            PrivateKey::SG02(key) => key.get_threshold(),
            PrivateKey::BZ03(key) => key.get_threshold(),
            PrivateKey::BLS04(key) => key.get_threshold()
        }
    }

    pub fn get_public_key(&self) -> PublicKey {
        match self {
            PrivateKey::SG02(key) => PublicKey::SG02(key.get_public_key()),
            PrivateKey::BZ03(key) => PublicKey::BZ03(key.get_public_key()),
            PrivateKey::BLS04(key) => PublicKey::BLS04(key.get_public_key()),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, rasn::ber::enc::Error> {
        encode(self)
    }

    pub fn deserialize(bytes: &Vec<u8>) -> Result<Self, ThresholdCryptoError> {
        let key = decode::<Self>(bytes);
        if key.is_err() {
            return Err(ThresholdCryptoError::DeserializationFailed)
        }

        return Ok(key.unwrap());
    }
}

impl Decode for PrivateKey {
    fn decode_with_tag<Dec: rasn::Decoder>(decoder: &mut Dec, tag: rasn::Tag) -> Result<Self, Dec::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let scheme = ThresholdScheme::from_id(u8::decode(sequence)?);
            let bytes = Vec::<u8>::decode(sequence)?;

            match scheme {
                ThresholdScheme::BLS04 => {
                    let key: Bls04PrivateKey = decode(&bytes).unwrap();
                    Ok(PrivateKey::BLS04(key))
                },
                ThresholdScheme::SG02 => {
                    let key: Sg02PrivateKey = decode(&bytes).unwrap();
                    Ok(PrivateKey::SG02(key))
                }, 
                ThresholdScheme::BZ03 => {
                    let key: Bz03PrivateKey = decode(&bytes).unwrap();
                    Ok(PrivateKey::BZ03(key))
                }, 
                ThresholdScheme::CKS05 => {
                    todo!();
                },
                ThresholdScheme::SH00 => {
                    todo!();
                },
                _ => {
                    panic!("unknown key encoding!");
                }
            }
        })
    }
}

impl Encode for PrivateKey {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        match self  {
            Self::BLS04(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::BLS04)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::SG02(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::SG02)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::BZ03(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::BZ03)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
        }
    }
}

#[derive(AsnType, Clone, PartialEq)]
#[rasn(enumerated)]
pub enum PublicKey {
    SG02(Sg02PublicKey),
    BZ03(Bz03PublicKey),
    BLS04(Bls04PublicKey)
}

impl Decode for PublicKey {
    fn decode_with_tag<Dec: rasn::Decoder>(decoder: &mut Dec, tag: rasn::Tag) -> Result<Self, Dec::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let scheme = ThresholdScheme::from_id(u8::decode(sequence)?);
            let bytes = Vec::<u8>::decode(sequence)?;

            match scheme {
                ThresholdScheme::BLS04 => {
                    let key: Bls04PublicKey = decode(&bytes).unwrap();
                    Ok(PublicKey::BLS04(key))
                },
                ThresholdScheme::SG02 => {
                    let key: Sg02PublicKey = decode(&bytes).unwrap();
                    Ok(PublicKey::SG02(key))
                }, 
                ThresholdScheme::BZ03 => {
                    let key: Bz03PublicKey = decode(&bytes).unwrap();
                    Ok(PublicKey::BZ03(key))
                }, 
                ThresholdScheme::CKS05 => {
                    todo!();
                },
                ThresholdScheme::SH00 => {
                    todo!();
                },
                _ => {
                    panic!("unknown key encoding!");
                }
            }
        })
    }
}

impl Encode for PublicKey {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        match self  {
            Self::BLS04(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::BLS04)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::SG02(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::SG02)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::BZ03(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::BZ03)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
        }
    }
}

impl PublicKey {
    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            PublicKey::SG02(_key) => ThresholdScheme::SG02,
            PublicKey::BZ03(_key) => ThresholdScheme::BZ03,
            PublicKey::BLS04(_key) => ThresholdScheme::BLS04,
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            PublicKey::SG02(key) => key.get_group(),
            PublicKey::BZ03(key) => key.get_group(),
            PublicKey::BLS04(key) => key.get_group()
        }
    }

    pub fn get_threshold(&self) -> u16 {
        match self {
            PublicKey::SG02(key) => key.get_threshold(),
            PublicKey::BZ03(key) => key.get_threshold(),
            PublicKey::BLS04(key) => key.get_threshold()
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, rasn::ber::enc::Error> {
        encode(self)
    }

    pub fn deserialize(bytes: &Vec<u8>) -> Result<Self, ThresholdCryptoError> {
        let key = decode::<Self>(bytes);
        if key.is_err() {
            return Err(ThresholdCryptoError::DeserializationFailed)
        }

        return Ok(key.unwrap());
    }
}

pub struct KeyGenerator {}

impl KeyGenerator {
    pub fn generate_keys(k: usize, n: usize, rng: &mut RNG, scheme: &ThresholdScheme, group: &Group) -> Result<Vec<PrivateKey>, ThresholdCryptoError> {
        match scheme {
            ThresholdScheme::BZ03 => {
                if !group.supports_pairings() {
                    return Err(ThresholdCryptoError::CurveDoesNotSupportPairings);
                }

                let x = BigImpl::new_rand(&group, &group.get_order(), rng);
                let mut y = GroupElement::new_ecp2(&group);
                y.pow(&x);

                let (shares, h) = shamir_share(&x, k, n, rng);
                let mut privateKeys = Vec::new();
                let publicKey = Bz03PublicKey::new(&group, n, k, &y, &h );

                for i in 0..shares.len() {
                    privateKeys.push(PrivateKey::BZ03(Bz03PrivateKey::new((i+1) as u16, &shares[i], &publicKey)))
                }

                return Result::Ok(privateKeys);
            },

            ThresholdScheme::SG02 => {
                let x = BigImpl::new_rand(group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big(&group, &x);

                let (shares, h): (Vec<BigImpl>, Vec<GroupElement>) = shamir_share(&x, k as usize, n as usize, rng);
                let mut privateKeys = Vec::new();

                let g_bar = GroupElement::new_rand(group, rng);

                let publicKey = Sg02PublicKey::new(n, k, group, &y,&h, &g_bar );

                for i in 0..shares.len() {
                    privateKeys.push(PrivateKey::SG02(Sg02PrivateKey::new((i+1).try_into().unwrap(), &shares[i], &publicKey)))
                }

                return Result::Ok(privateKeys);
            },

            ThresholdScheme::BLS04 => {
                if !group.supports_pairings() {
                    return Err(ThresholdCryptoError::CurveDoesNotSupportPairings);
                }

                let x = BigImpl::new_rand(&group, &group.get_order(), rng);
                let mut y = GroupElement::new(&group);
                y.pow(&x);

                let (shares, h) = shamir_share(&x, k, n, rng);
                let mut privateKeys = Vec::new();
                let publicKey = Bls04PublicKey::new(&group, n, k, &y, &h );

                for i in 0..shares.len() {
                    privateKeys.push(PrivateKey::BLS04(Bls04PrivateKey::new((i+1) as u16, &shares[i], &publicKey)))
                }

                return Result::Ok(privateKeys);
            },

            ThresholdScheme::CKS05 => {
                todo!();
            },

            ThresholdScheme::FROST => {
                todo!();
            },

            ThresholdScheme::SH00 => {
                todo!();
            }
        }
    }
}