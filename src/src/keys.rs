use std::convert::TryInto;

use rasn::AsnType;
use rasn::Decode;
use rasn::Encode;
use rasn::Encoder;
use rasn::der::decode;

use crate::dl_schemes::bigint::BigImpl;
use crate::dl_schemes::ciphers::sg02::Sg02PrivateKey;
use crate::dl_schemes::ciphers::sg02::Sg02PublicKey;
use crate::dl_schemes::common::shamir_share;
use crate::dl_schemes::dl_groups::dl_group::GroupElement;
use crate::dl_schemes::dl_groups::dl_group::Group;
use crate::interface::Serializable;
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
    SG02(Sg02PrivateKey)
}

impl PrivateKey {
    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            SG02 => ThresholdScheme::SG02
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            PrivateKey::SG02(key) => key.get_group()
        }
    }

    pub fn get_threshold(&self) -> u16 {
        match self {
            PrivateKey::SG02(key) => key.get_threshold()
        }
    }

    pub fn get_public_key(&self) -> PublicKey {
        match self {
            PrivateKey::SG02(key) => PublicKey::SG02(key.get_public_key()) 
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, rasn::ber::enc::Error> {
        match self {
            PrivateKey::SG02(key) => key.serialize()
        }
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
                    Ok(PrivateKey::SG02(key))
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
            Self::SG02(key) => {
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
    SG02(Sg02PublicKey)
}

impl PublicKey {
    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            PublicKey::SG02(key) => ThresholdScheme::SG02
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            PublicKey::SG02(key) => key.get_group()
        }
    }

    pub fn get_threshold(&self) -> u16 {
        match self {
            PublicKey::SG02(key) => key.get_threshold()
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, rasn::ber::enc::Error> {
        match self {
            PublicKey::SG02(key) => key.serialize()
        }
    }

    pub fn deserialize(bytes: &Vec<u8>) -> Self {
        //TODO: fix
        PublicKey::SG02(Sg02PublicKey::deserialize(bytes).unwrap())
    }
}

pub struct KeyGenerator {}

impl KeyGenerator {
    pub fn generate_keys(k: usize, n: usize, rng: &mut RNG, scheme: &ThresholdScheme, group: &Group) -> Vec<PrivateKey> {
        match scheme {
            ThresholdScheme::BZ03 => {
                todo!();
            },

            ThresholdScheme::SG02 => {
                let x = BigImpl::new_rand(group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big(&group, &x);

                let (shares, h): (Vec<BigImpl>, Vec<GroupElement>) = shamir_share(&x, k, n, rng);
                let mut privateKeys = Vec::new();

                let g_bar = GroupElement::new_rand(group, rng);

                let publicKey = Sg02PublicKey::new(n as u16, k as u16, group, &y,&h, &g_bar );

                for i in 0..shares.len() {
                    privateKeys.push(PrivateKey::SG02(Sg02PrivateKey::new((i+1).try_into().unwrap(), &shares[i], &publicKey)))
                }

                return privateKeys;
            },

            ThresholdScheme::BLS04 => {
                todo!();
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