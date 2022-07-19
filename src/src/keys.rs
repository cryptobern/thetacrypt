use std::convert::TryInto;
use std::fmt::format;
use std::vec;

use rasn::AsnType;
use rasn::Decode;
use rasn::Encode;
use rasn::Encoder;
use rasn::der::decode;
use serde::ser::SerializeSeq;

use crate::dl_schemes::bigint::BigImpl;
use crate::dl_schemes::ciphers::sg02::Sg02PrivateKey;
use crate::dl_schemes::ciphers::sg02::Sg02PublicKey;
use crate::dl_schemes::common::shamir_share;
use crate::dl_schemes::dl_groups::dl_group::GroupElement;
use crate::proto::scheme_types::Group;
use crate::interface::Serializable;
use super::proto::scheme_types::ThresholdScheme;
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


#[derive(AsnType, Clone, PartialEq)]
#[rasn(enumerated)]
pub enum PrivateKey {
    Sg02(Sg02PrivateKey)
}

impl PrivateKey {
    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Sg02 => ThresholdScheme::Sg02
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            PrivateKey::Sg02(key) => key.get_group()
        }
    }

    pub fn get_threshold(&self) -> u16 {
        match self {
            PrivateKey::Sg02(key) => key.get_threshold()
        }
    }

    pub fn get_id(&self) -> u16 {
        match self {
            PrivateKey::Sg02(key) => key.get_id()
        }
    }

    pub fn get_public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Sg02(key) => PublicKey::Sg02(key.get_public_key()) 
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, rasn::ber::enc::Error> {
        match self {
            PrivateKey::Sg02(key) => key.serialize()
        }
    }

    pub fn deserialize(bytes: &Vec<u8>) -> Self {
        //TODO: fix
        PrivateKey::Sg02(Sg02PrivateKey::deserialize(bytes).unwrap())
    }

}

impl serde::Serialize for PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        match self.serialize(){
            // Ok(key_bytes) => { serializer.serialize_bytes(&key_bytes) },
            Ok(key_bytes) => { 
                let mut seq = serializer.serialize_seq(Some(key_bytes.len()))?;
                for element in key_bytes.iter() {
                    seq.serialize_element(element)?;
                }
                seq.end()
            },
            Err(err) => { Err(serde::ser::Error::custom(format!("Could not serialize PrivateKey. err: {:?}", err))) }
        }
    }
}

struct PrivateKeyVisitor;
impl<'de> serde::de::Visitor<'de> for PrivateKeyVisitor {
    type Value = PrivateKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of bytes")
    }

    // fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    //     where E: serde::de::Error, {
    //     Ok(PrivateKey::deserialize(&Vec::from(v)))
    // }

    // fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    //     where E: serde::de::Error, {
    //         match PrivateKey::deserialize(&v) {
    //             //TODO: fix
    //             PrivateKey::Sg02(sk) => { Ok(PrivateKey::Sg02(sk)) },
    //             _ => todo!()
    //         }
    // }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where A: serde::de::SeqAccess<'de>, {
        let mut key_vec = Vec::new();
        while let Ok(Some(next)) = seq.next_element() {
            key_vec.push(next);
        }
        let key = PrivateKey::deserialize(&key_vec);  //TODO: fix
        Ok(key)
    }
}


impl<'de> serde::Deserialize<'de> for PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        // deserializer.deserialize_bytes(BytesVisitor)
        deserializer.deserialize_seq(PrivateKeyVisitor)
    }
}


impl Decode for PrivateKey {
    fn decode_with_tag<Dec: rasn::Decoder>(decoder: &mut Dec, tag: rasn::Tag) -> Result<Self, Dec::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let keyType = u8::decode(sequence)?;
            let bytes = Vec::<u8>::decode(sequence)?;

            match keyType {
                0 => {
                    todo!();
                },
                1 => {
                    let key: Sg02PrivateKey = decode(&bytes).unwrap();
                    Ok(PrivateKey::Sg02(key))
                }, 
                2 => {
                    todo!();
                }, 
                3 => {
                    todo!();
                },
                4 => {
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
            Self::Sg02(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (1 as u8).encode(sequence)?;
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
    Sg02(Sg02PublicKey)
}

impl PublicKey {
    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            PublicKey::Sg02(key) => ThresholdScheme::Sg02
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            PublicKey::Sg02(key) => key.get_group()
        }
    }

    pub fn get_threshold(&self) -> u16 {
        match self {
            PublicKey::Sg02(key) => key.get_threshold()
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, rasn::ber::enc::Error> {
        match self {
            PublicKey::Sg02(key) => key.serialize()
        }
    }

    pub fn deserialize(bytes: &Vec<u8>) -> Self {
        //TODO: fix
        PublicKey::Sg02(Sg02PublicKey::deserialize(bytes).unwrap())
    }
}

pub struct KeyGenerator {}

impl KeyGenerator {
    pub fn generate_keys(k: usize, n: usize, rng: &mut RNG, scheme: &ThresholdScheme, group: &Group) -> Vec<PrivateKey> {
        match scheme {
            ThresholdScheme::Bz03 => {
                todo!();
            },

            ThresholdScheme::Sg02 => {
                let x = BigImpl::new_rand(group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big(&group, &x);

                let (shares, h): (Vec<BigImpl>, Vec<GroupElement>) = shamir_share(&x, k, n, rng);
                let mut privateKeys = Vec::new();

                let g_bar = GroupElement::new_rand(group, rng);

                let publicKey = Sg02PublicKey::new(n as u16, k as u16, group, &y,&h, &g_bar );

                for i in 0..shares.len() {
                    privateKeys.push(PrivateKey::Sg02(Sg02PrivateKey::new((i+1).try_into().unwrap(), &shares[i], &publicKey)))
                }

                return privateKeys;
            },

            ThresholdScheme::Bls04 => {
                todo!();
            },

            ThresholdScheme::Cks05 => {
                todo!();
            },

            ThresholdScheme::Frost => {
                todo!();
            },

            ThresholdScheme::Sh00 => {
                todo!();
            }
        }
    }
}