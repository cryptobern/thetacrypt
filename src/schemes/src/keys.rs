use std::convert::TryInto;

use std::fmt::format;
use std::vec;
use std::time::Instant;

use derive::Serializable;
use rasn::AsnType;
use rasn::Decode;
use rasn::Encode;
use rasn::Encoder;
use rasn::ber::encode;
use rasn::der::decode;
use serde::ser::SerializeSeq;

use crate::BIGINT;
use crate::ONE;
use crate::dl_schemes::bigint::BigImpl;
use crate::dl_schemes::ciphers::bz03::Bz03PrivateKey;
use crate::dl_schemes::ciphers::bz03::Bz03PublicKey;
use crate::dl_schemes::ciphers::sg02::Sg02PrivateKey;
use crate::dl_schemes::ciphers::sg02::Sg02PublicKey;
use crate::dl_schemes::coins::cks05::Cks05PrivateKey;
use crate::dl_schemes::coins::cks05::Cks05PublicKey;
use crate::dl_schemes::common::shamir_share;
use crate::dl_schemes::signatures::bls04::Bls04PrivateKey;
use crate::dl_schemes::signatures::bls04::Bls04PublicKey;
use crate::dl_schemes::signatures::frost::FrostPrivateKey;
use crate::dl_schemes::signatures::frost::FrostPublicKey;
use crate::group::GroupElement;
use crate::group::Group;
use crate::interface::Serializable;
use crate::interface::ThresholdCryptoError;
use crate::interface::ThresholdScheme;
use crate::rand::RNG;
use crate::rsa_schemes::bigint::RsaBigInt;
use crate::rsa_schemes::common::fac;
use crate::rsa_schemes::common::gen_strong_prime;
use crate::rsa_schemes::common::shamir_share_rsa;

use crate::rsa_schemes::signatures::sh00::Sh00PrivateKey;
use crate::rsa_schemes::signatures::sh00::Sh00PublicKey;
use crate::rsa_schemes::signatures::sh00::Sh00VerificationKey;

const DEBUG:bool = true;

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

#[derive(AsnType, Clone, Debug)]
#[rasn(enumerated)]
pub enum PrivateKey {
    Sg02(Sg02PrivateKey),
    Bz03(Bz03PrivateKey),
    Bls04(Bls04PrivateKey),
    Cks05(Cks05PrivateKey),
    Sh00(Sh00PrivateKey),
    Frost(FrostPrivateKey)
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Sg02(l0), Self::Sg02(r0)) => l0.eq(r0),
            (Self::Bz03(l0), Self::Bz03(r0)) => l0.eq(r0),
            (Self::Bls04(l0), Self::Bls04(r0)) => l0.eq(r0),
            (Self::Sh00(l0), Self::Sh00(r0)) => l0.eq(r0),
            (Self::Frost(l0), Self::Frost(r0)) => l0.eq(r0),
            (Self::Cks05(l0), Self::Cks05(r0)) => l0.eq(r0),
            _ => false
        }
    }
}

impl PrivateKey {
    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            Self::Sg02(_) => ThresholdScheme::Sg02,
            Self::Bz03(_) => ThresholdScheme::Bz03,
            Self::Bls04(_) => ThresholdScheme::Bls04,
            Self::Cks05(_) => ThresholdScheme::Cks05,
            Self::Sh00(_) => ThresholdScheme::Sh00,
            Self::Frost(_) => ThresholdScheme::Frost
        }
    }

    pub fn get_id(&self) -> u16 {
        match self {
            PrivateKey::Sg02(key) => key.get_id(),
            PrivateKey::Bz03(key) => key.get_id(),
            PrivateKey::Bls04(key) => key.get_id(),
            PrivateKey::Cks05(key) => key.get_id(),
            PrivateKey::Sh00(key) => key.get_id(),
            PrivateKey::Frost(key) => key.get_id()
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            PrivateKey::Sg02(key) => key.get_group(),
            PrivateKey::Bz03(key) => key.get_group(),
            PrivateKey::Bls04(key) => key.get_group(),
            PrivateKey::Cks05(key) => key.get_group(),
            PrivateKey::Sh00(key) => key.get_group(),
            PrivateKey::Frost(key) => key.get_group()
        }
    }

    pub fn get_threshold(&self) -> u16 {
        match self {
            PrivateKey::Sg02(key) => key.get_threshold(),
            PrivateKey::Bz03(key) => key.get_threshold(),
            PrivateKey::Bls04(key) => key.get_threshold(),
            PrivateKey::Cks05(key) => key.get_threshold(),
            PrivateKey::Sh00(key) => key.get_threshold(),
            PrivateKey::Frost(key) => key.get_threshold()
        }
    }

    pub fn get_public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Sg02(key) => PublicKey::Sg02(key.get_public_key()),
            PrivateKey::Bz03(key) => PublicKey::Bz03(key.get_public_key()),
            PrivateKey::Bls04(key) => PublicKey::Bls04(key.get_public_key()),
            PrivateKey::Cks05(key) => PublicKey::Cks05(key.get_public_key()),
            PrivateKey::Sh00(key) => PublicKey::Sh00(key.get_public_key()),
            PrivateKey::Frost(key) => PublicKey::Frost(key.get_public_key())
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
        Ok(key.unwrap())
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
            let scheme = ThresholdScheme::from_id(u8::decode(sequence)?);
            let bytes = Vec::<u8>::decode(sequence)?;

            match scheme {
                ThresholdScheme::Bls04 => {
                    let key: Bls04PrivateKey = decode(&bytes).unwrap();
                    Ok(PrivateKey::Bls04(key))
                },
                ThresholdScheme::Sg02 => {
                    let key: Sg02PrivateKey = decode(&bytes).unwrap();
                    Ok(PrivateKey::Sg02(key))
                }, 
                ThresholdScheme::Bz03 => {
                    let key: Bz03PrivateKey = decode(&bytes).unwrap();
                    Ok(PrivateKey::Bz03(key))
                }, 
                ThresholdScheme::Cks05 => {
                    let key: Cks05PrivateKey = decode(&bytes).unwrap();
                    Ok(PrivateKey::Cks05(key))
                },
                ThresholdScheme::Sh00 => {
                    let key: Sh00PrivateKey = decode(&bytes).unwrap();
                    Ok(PrivateKey::Sh00(key))
                },
                ThresholdScheme::Frost => {
                    let key: FrostPrivateKey = decode(&bytes).unwrap();
                    Ok(PrivateKey::Frost(key))
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
            Self::Bls04(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Bls04)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::Sg02(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Sg02)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::Bz03(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Bz03)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::Cks05(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Cks05)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::Sh00(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Sh00)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::Frost(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Frost)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
        }
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
    Frost(FrostPublicKey)
}

impl Decode for PublicKey {
    fn decode_with_tag<Dec: rasn::Decoder>(decoder: &mut Dec, tag: rasn::Tag) -> Result<Self, Dec::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let scheme = ThresholdScheme::from_id(u8::decode(sequence)?);
            let bytes = Vec::<u8>::decode(sequence)?;

            match scheme {
                ThresholdScheme::Bls04 => {
                    let key: Bls04PublicKey = decode(&bytes).unwrap();
                    Ok(PublicKey::Bls04(key))
                },
                ThresholdScheme::Sg02 => {
                    let key: Sg02PublicKey = decode(&bytes).unwrap();
                    Ok(PublicKey::Sg02(key))
                }, 
                ThresholdScheme::Bz03 => {
                    let key: Bz03PublicKey = decode(&bytes).unwrap();
                    Ok(PublicKey::Bz03(key))
                }, 
                ThresholdScheme::Cks05 => {
                    let key: Cks05PublicKey = decode(&bytes).unwrap();
                    Ok(PublicKey::Cks05(key))
                },
                ThresholdScheme::Sh00 => {
                    let key: Sh00PublicKey = decode(&bytes).unwrap();
                    Ok(PublicKey::Sh00(key))
                },
                ThresholdScheme::Frost => {
                    let key: FrostPublicKey = decode(&bytes).unwrap();
                    Ok(PublicKey::Frost(key))
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
            Self::Bls04(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Bls04)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::Sg02(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Sg02)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::Bz03(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Bz03)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },
            Self::Cks05(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Cks05)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },

            Self::Sh00(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Sh00)).encode(sequence)?;
                    key.serialize().unwrap().encode(sequence)?;
                    Ok(())
                })?;
                Ok(())
            },

            Self::Frost(key) => {
                encoder.encode_sequence(tag, |sequence| {
                    (ThresholdScheme::get_id(&ThresholdScheme::Frost)).encode(sequence)?;
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
            PublicKey::Sg02(_key) => ThresholdScheme::Sg02,
            PublicKey::Bz03(_key) => ThresholdScheme::Bz03,
            PublicKey::Bls04(_key) => ThresholdScheme::Bls04,
            PublicKey::Cks05(_key) => ThresholdScheme::Cks05,
            PublicKey::Sh00(_key) => ThresholdScheme::Sh00,
            PublicKey::Frost(_key) => ThresholdScheme::Frost,
        }
    }

    pub fn get_group(&self) -> Group {
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

pub struct KeyParams {
    e: RsaBigInt
}

impl KeyParams {
    pub fn new() -> Self {
        return Self { e: BIGINT!(65537) }
    }

    pub fn set_e(&mut self, e: &RsaBigInt) {
        self.e.set(e);
    }
}

pub struct IntKeyStore {
    pk: PublicKey,
    h: Option<Vec<GroupElement>>,
    g_bar: Option<GroupElement>,
    xi: Option<Vec<BigImpl>>,
    si: Option<Vec<(u16, RsaBigInt)>>,
    m: Option<RsaBigInt>
}

impl IntKeyStore {
    pub fn new(pk: PublicKey, xi: Option<Vec<BigImpl>>, si:Option<Vec<(u16, RsaBigInt)>>, m:Option<RsaBigInt>, h: Option<Vec<GroupElement>>, g_bar: Option<GroupElement>) -> Self {
        Self {pk, xi, si, m, h, g_bar}
    }

    pub fn get_public_key(&self) -> PublicKey {
        self.pk.clone()
    }

    pub fn get_serialized_pubkey(&self) -> Vec<u8> {
        self.pk.serialize().unwrap()
    }

    pub fn get_private_key(&self, index:u16) -> PrivateKey {
        if index < 1 || index > self.pk.get_n() {
            panic!("Private key index has to be between 1 and n");
        }
        match &self.pk {
            PublicKey::Sg02(key) => PrivateKey::Sg02(Sg02PrivateKey::new(index, &self.xi.as_ref().unwrap()[(index-1) as usize], &key.clone())),
            PublicKey::Bz03(key) => PrivateKey::Bz03(Bz03PrivateKey::new(index, &self.xi.as_ref().unwrap()[(index-1) as usize], &key.clone())),
            PublicKey::Bls04(key) => PrivateKey::Bls04(Bls04PrivateKey::new(index, &self.xi.as_ref().unwrap()[(index-1) as usize], &key.clone())),
            PublicKey::Cks05(key) => PrivateKey::Cks05(Cks05PrivateKey::new(index, &self.xi.as_ref().unwrap()[(index-1) as usize], &key.clone())),
            PublicKey::Sh00(key) => PrivateKey::Sh00(Sh00PrivateKey::new(index, self.m.as_ref().unwrap(), &self.si.as_ref().unwrap()[(index-1) as usize].1, &key.clone())),
            PublicKey::Frost(key) => PrivateKey::Frost(FrostPrivateKey::new(index as usize, &self.xi.as_ref().unwrap()[(index-1) as usize], &key.clone())),
        }
    }

    pub fn get_serialized_private_key(&self, index:u16) -> Result<Vec<u8>, rasn::ber::enc::Error> {
        if index < 1 || index > self.pk.get_n() {
            panic!("Private key index has to be between 1 and n");
        }
        self.get_private_key(index).serialize()
    }
}

impl KeyGenerator {
    pub fn generate_keys(k: usize, n: usize, rng: &mut RNG, scheme: &ThresholdScheme, group: &Group, params: &Option<KeyParams>) -> Result<Vec<PrivateKey>, ThresholdCryptoError> {
        match scheme {
            ThresholdScheme::Bz03 => {
                if !group.supports_pairings() {
                    return Err(ThresholdCryptoError::CurveDoesNotSupportPairings);
                }

                if !group.is_dl() {
                    return Err(ThresholdCryptoError::IncompatibleGroup);
                } 

                let x = BigImpl::new_rand(&group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big_ecp2(&group, &x);

                let (shares, h) = shamir_share(&x, k, n, rng);
                let mut private_keys = Vec::new();
                let public_key = Bz03PublicKey::new(&group, n, k, &y, &h );

                for i in 0..shares.len() {
                    private_keys.push(PrivateKey::Bz03(Bz03PrivateKey::new((i+1) as u16, &shares[i], &public_key)))
                }

                return Result::Ok(private_keys);
            },

            ThresholdScheme::Sg02 => {
                if !group.is_dl() {
                    return Err(ThresholdCryptoError::IncompatibleGroup);
                } 

                let x = BigImpl::new_rand(group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big(&group, &x);

                let (shares, h): (Vec<BigImpl>, Vec<GroupElement>) = shamir_share(&x, k as usize, n as usize, rng);
                let mut private_keys = Vec::new();

                let g_bar = GroupElement::new_rand(group, rng);

                let public_key = Sg02PublicKey::new(n, k, group, &y,&h, &g_bar );

                for i in 0..shares.len() {
                    private_keys.push(PrivateKey::Sg02(Sg02PrivateKey::new((i+1).try_into().unwrap(), &shares[i], &public_key)))
                }

                return Result::Ok(private_keys);
            },

            ThresholdScheme::Bls04 => {
                if !group.supports_pairings() {
                    return Err(ThresholdCryptoError::CurveDoesNotSupportPairings);
                }

                if !group.is_dl() {
                    return Err(ThresholdCryptoError::IncompatibleGroup);
                } 

                let x = BigImpl::new_rand(&group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big(&group, &x);

                let (shares, h) = shamir_share(&x, k, n, rng);
                let mut private_keys = Vec::new();
                let public_key = Bls04PublicKey::new(&group, n, k, &y, &h );

                for i in 0..shares.len() {
                    private_keys.push(PrivateKey::Bls04(Bls04PrivateKey::new((i+1) as u16, &shares[i], &public_key)))
                }

                return Result::Ok(private_keys);
            },

            ThresholdScheme::Cks05 => {
                if !group.is_dl() {
                    return Err(ThresholdCryptoError::IncompatibleGroup);
                } 

                let x = BigImpl::new_rand(&group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big(&group, &x);

                let (shares, h): (Vec<BigImpl>, Vec<GroupElement>) = shamir_share(&x, k as usize, n as usize, rng);
                let mut private_keys = Vec::new();

                let public_key = Cks05PublicKey::new(group, n, k, &y,&h );

                for i in 0..shares.len() {
                    private_keys.push(PrivateKey::Cks05(Cks05PrivateKey::new((i+1) as u16, &shares[i], &public_key)));
                }

                return Ok(private_keys);

            },

            ThresholdScheme::Frost => {
                let x = BigImpl::new_rand(group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big(&group, &x);
            
                let (shares, h): (Vec<BigImpl>, Vec<GroupElement>) = shamir_share(&x, k as usize, n as usize, rng);
                let mut private_keys = Vec::new();
            
                let public_key = FrostPublicKey::new(n, k, group, &y, &h );
            
                for i in 0..shares.len() {
                    private_keys.push(PrivateKey::Frost(FrostPrivateKey::new((i+1).try_into().unwrap(), &shares[i], &public_key)));
                }
            
                return Result::Ok(private_keys);
            },

            ThresholdScheme::Sh00 => {
                if group.is_dl() {
                    return Err(ThresholdCryptoError::IncompatibleGroup);
                }

                let mut e = BIGINT!(65537);

                if params.is_some() {
                    e.set(&params.as_ref().unwrap().e);
                }

                let modsize: usize;
                match group {
                    Group::Rsa512 => modsize = 512,
                    Group::Rsa1024 => modsize = 1024,
                    Group::Rsa2048 => modsize = 2048,
                    &Group::Rsa4096 => modsize = 4096,
                    _ => return Err(ThresholdCryptoError::WrongGroup)
                }

                let PLEN = modsize/2 - 2; 
                
                let mut p1 = RsaBigInt::new_rand(rng, PLEN);
                let mut q1 = RsaBigInt::new_rand(rng, PLEN);

                let mut p = RsaBigInt::new();
                let mut q = RsaBigInt::new();

                if DEBUG { println!("generating strong primes..."); }

                let now = Instant::now();
                gen_strong_prime(&mut p1, &mut p, &e, rng, PLEN);
                let elapsed_time = now.elapsed().as_millis();
                if DEBUG { println!("found first prime p in {}ms: {}", elapsed_time, p.to_string()); }
                
                let now = Instant::now();
                gen_strong_prime(&mut q1, &mut q, &e,  rng, PLEN);
                let elapsed_time = now.elapsed().as_millis();
                if DEBUG { println!("found second prime q in {}ms: {}", elapsed_time, q.to_string()); }
                
                let N = p.mul(&q);
                let m = p1.mul(&q1);

                let v = RsaBigInt::new_rand(rng, modsize - 1).pow(2).rmod(&N);

                let d = e.inv_mod(&m);

                let delta = fac(n);
                let (xi, vi) = shamir_share_rsa(&d, k, n, &N, &m, &v, modsize, rng);
                
                let mut u;
                let mut up;
                let mut uq;
                loop {
                    u = RsaBigInt::new_rand(rng, modsize - 1);
                    up = u.pow_mod(&p1, &p);
                    uq = u.pow_mod(&q1, &q);
                    if up.equals(&ONE!()) != uq.equals(&ONE!())  {
                        break;
                    }
                }

                let verificationKey = Sh00VerificationKey::new(v, vi, u);
                let pubkey = Sh00PublicKey::new(n as u16, k as u16, N,  e.clone(), verificationKey, delta, modsize);
                
                let mut pks: Vec<PrivateKey> = Vec::new();
                for i in 0..n {
                    pks.push(PrivateKey::Sh00(Sh00PrivateKey::new(xi[i].0,&m, &xi[i].1, &pubkey)))
                }
                Ok(pks)
            }
        }
    }

    pub fn generate_keys_min(k: usize, n: usize, rng: &mut RNG, scheme: &ThresholdScheme, group: &Group, params: &Option<KeyParams>) -> Result<IntKeyStore, ThresholdCryptoError> {
        match scheme {
            ThresholdScheme::Bz03 => {
                if !group.supports_pairings() {
                    return Err(ThresholdCryptoError::CurveDoesNotSupportPairings);
                }

                if !group.is_dl() {
                    return Err(ThresholdCryptoError::IncompatibleGroup);
                } 

                let x = BigImpl::new_rand(&group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big_ecp2(&group, &x);

                let (shares, h) = shamir_share(&x, k, n, rng);
                let public_key = Bz03PublicKey::new(&group, n, k, &y, &h );

                let keystore = IntKeyStore::new(PublicKey::Bz03(public_key.clone()), Option::Some(shares), Option::None, Option::None, Option::Some(h), Option::None);

                return Result::Ok(keystore);
            },

            ThresholdScheme::Sg02 => {
                if !group.is_dl() {
                    return Err(ThresholdCryptoError::IncompatibleGroup);
                } 

                let x = BigImpl::new_rand(group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big(&group, &x);

                let (shares, h): (Vec<BigImpl>, Vec<GroupElement>) = shamir_share(&x, k as usize, n as usize, rng);

                let g_bar = GroupElement::new_rand(group, rng);

                let public_key = Sg02PublicKey::new(n, k, group, &y,&h, &g_bar );

                let keystore = IntKeyStore::new(PublicKey::Sg02(public_key.clone()), Option::Some(shares), Option::None, Option::None, Option::Some(h), Option::Some(g_bar));

                return Result::Ok(keystore);
            },

            ThresholdScheme::Bls04 => {
                if !group.supports_pairings() {
                    return Err(ThresholdCryptoError::CurveDoesNotSupportPairings);
                }

                if !group.is_dl() {
                    return Err(ThresholdCryptoError::IncompatibleGroup);
                } 

                let x = BigImpl::new_rand(&group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big(&group, &x);

                let (shares, h) = shamir_share(&x, k, n, rng);
                let public_key = Bls04PublicKey::new(&group, n, k, &y, &h );

                let keystore = IntKeyStore::new(PublicKey::Bls04(public_key.clone()), Option::Some(shares), Option::None, Option::None, Option::Some(h), Option::None);

                return Result::Ok(keystore);
            },

            ThresholdScheme::Cks05 => {
                if !group.is_dl() {
                    return Err(ThresholdCryptoError::IncompatibleGroup);
                } 

                let x = BigImpl::new_rand(&group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big(&group, &x);

                let (shares, h): (Vec<BigImpl>, Vec<GroupElement>) = shamir_share(&x, k as usize, n as usize, rng);

                let public_key = Cks05PublicKey::new(group, n, k, &y,&h );

                let keystore = IntKeyStore::new(PublicKey::Cks05(public_key.clone()), Option::Some(shares), Option::None, Option::None, Option::Some(h), Option::None);

                return Result::Ok(keystore);

            },

            ThresholdScheme::Frost => {
                let x = BigImpl::new_rand(group, &group.get_order(), rng);
                let y = GroupElement::new_pow_big(&group, &x);
            
                let (shares, h): (Vec<BigImpl>, Vec<GroupElement>) = shamir_share(&x, k as usize, n as usize, rng);
            
                let public_key = FrostPublicKey::new(n, k, group, &y, &h );
            
                let keystore = IntKeyStore::new(PublicKey::Frost(public_key.clone()), Option::Some(shares), Option::None, Option::None, Option::Some(h), Option::None);

                return Result::Ok(keystore);
            },

            ThresholdScheme::Sh00 => {
                if group.is_dl() {
                    return Err(ThresholdCryptoError::IncompatibleGroup);
                }

                let mut e = BIGINT!(65537);

                if params.is_some() {
                    e.set(&params.as_ref().unwrap().e);
                }

                let modsize: usize;
                match group {
                    Group::Rsa512 => modsize = 512,
                    Group::Rsa1024 => modsize = 1024,
                    Group::Rsa2048 => modsize = 2048,
                    &Group::Rsa4096 => modsize = 4096,
                    _ => return Err(ThresholdCryptoError::WrongGroup)
                }

                let PLEN = modsize/2 - 2; 
                
                let mut p1 = RsaBigInt::new_rand(rng, PLEN);
                let mut q1 = RsaBigInt::new_rand(rng, PLEN);

                let mut p = RsaBigInt::new();
                let mut q = RsaBigInt::new();

                if DEBUG { println!("generating strong primes..."); }

                let now = Instant::now();
                gen_strong_prime(&mut p1, &mut p, &e, rng, PLEN);
                let elapsed_time = now.elapsed().as_millis();
                if DEBUG { println!("found first prime p in {}ms: {}", elapsed_time, p.to_string()); }
                
                let now = Instant::now();
                gen_strong_prime(&mut q1, &mut q, &e,  rng, PLEN);
                let elapsed_time = now.elapsed().as_millis();
                if DEBUG { println!("found second prime q in {}ms: {}", elapsed_time, q.to_string()); }
                
                let N = p.mul(&q);
                let m = p1.mul(&q1);

                let v = RsaBigInt::new_rand(rng, modsize - 1).pow(2).rmod(&N);

                let d = e.inv_mod(&m);

                let delta = fac(n);
                let (xi, vi) = shamir_share_rsa(&d, k, n, &N, &m, &v, modsize, rng);
                
                let mut u;
                let mut up;
                let mut uq;
                loop {
                    u = RsaBigInt::new_rand(rng, modsize - 1);
                    up = u.pow_mod(&p1, &p);
                    uq = u.pow_mod(&q1, &q);
                    if up.equals(&ONE!()) != uq.equals(&ONE!())  {
                        break;
                    }
                }

                let verificationKey = Sh00VerificationKey::new(v, vi, u);
                let pubkey = Sh00PublicKey::new(n as u16, k as u16, N,  e.clone(), verificationKey, delta, modsize);


                let keystore = IntKeyStore::new(PublicKey::Sh00(pubkey.clone()), Option::None, Option::Some(xi), Option::Some(m), Option::None, Option::None);

                Ok(keystore)
            }
        }
    }
}