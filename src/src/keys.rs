use std::convert::TryInto;
use std::time::Instant;

use derive::Serializable;
use rasn::AsnType;
use rasn::Decode;
use rasn::Encode;
use rasn::Encoder;
use rasn::ber::encode;
use rasn::der::decode;

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
use crate::group::GroupElement;
use crate::proto::scheme_types::Group;
use crate::interface::Serializable;
use crate::interface::ThresholdCryptoError;
use crate::proto::scheme_types::ThresholdScheme;
use crate::rand::RNG;
use crate::rsa_schemes::bigint::RsaBigInt;
use crate::rsa_schemes::common::fac;
use crate::rsa_schemes::common::gen_strong_prime;
use crate::rsa_schemes::common::shamir_share_rsa;

use crate::rsa_schemes::signatures::sh00::Sh00PrivateKey;
use crate::rsa_schemes::signatures::sh00::Sh00PublicKey;
use crate::rsa_schemes::signatures::sh00::Sh00VerificationKey;

const DEBUG:bool = false;

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
    Sg02(Sg02PrivateKey),
    Bz03(Bz03PrivateKey),
    Bls04(Bls04PrivateKey),
    Cks05(Cks05PrivateKey),
    Sh00(Sh00PrivateKey)
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Sg02(l0), Self::Sg02(r0)) => l0.eq(r0),
            (Self::Bz03(l0), Self::Bz03(r0)) => l0.eq(r0),
            (Self::Bls04(l0), Self::Bls04(r0)) => l0.eq(r0),
            (Self::Sh00(l0), Self::Sh00(r0)) => l0.eq(r0),
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
            Self::Sh00(_) => ThresholdScheme::Sh00
        }
    }

    pub fn get_id(&self) -> u16 {
        match self {
            PrivateKey::Sg02(key) => key.get_id(),
            PrivateKey::Bz03(key) => key.get_id(),
            PrivateKey::Bls04(key) => key.get_id(),
            PrivateKey::Cks05(key) => key.get_id(),
            PrivateKey::Sh00(key) => key.get_id()
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            PrivateKey::Sg02(key) => key.get_group(),
            PrivateKey::Bz03(key) => key.get_group(),
            PrivateKey::Bls04(key) => key.get_group(),
            PrivateKey::Cks05(key) => key.get_group(),
            PrivateKey::Sh00(key) => key.get_group()
        }
    }

    pub fn get_threshold(&self) -> u16 {
        match self {
            PrivateKey::Sg02(key) => key.get_threshold(),
            PrivateKey::Bz03(key) => key.get_threshold(),
            PrivateKey::Bls04(key) => key.get_threshold(),
            PrivateKey::Cks05(key) => key.get_threshold(),
            PrivateKey::Sh00(key) => key.get_threshold()
        }
    }

    pub fn get_public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Sg02(key) => PublicKey::Sg02(key.get_public_key()),
            PrivateKey::Bz03(key) => PublicKey::Bz03(key.get_public_key()),
            PrivateKey::Bls04(key) => PublicKey::Bls04(key.get_public_key()),
            PrivateKey::Cks05(key) => PublicKey::Cks05(key.get_public_key()),
            PrivateKey::Sh00(key) => PublicKey::Sh00(key.get_public_key())
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
        }
    }
}

#[derive(AsnType, Clone, PartialEq)]
#[rasn(enumerated)]
pub enum PublicKey {
    Sg02(Sg02PublicKey),
    Bz03(Bz03PublicKey),
    Bls04(Bls04PublicKey),
    Cks05(Cks05PublicKey),
    Sh00(Sh00PublicKey)
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
        }
    }

    pub fn get_group(&self) -> Group {
        match self {
            PublicKey::Sg02(key) => key.get_group(),
            PublicKey::Bz03(key) => key.get_group(),
            PublicKey::Bls04(key) => key.get_group(),
            PublicKey::Cks05(key) => key.get_group(),
            PublicKey::Sh00(key) => key.get_group(),
        }
    }

    pub fn get_threshold(&self) -> u16 {
        match self {
            PublicKey::Sg02(key) => key.get_threshold(),
            PublicKey::Bz03(key) => key.get_threshold(),
            PublicKey::Bls04(key) => key.get_threshold(),
            PublicKey::Cks05(key) => key.get_threshold(),
            PublicKey::Sh00(key) => key.get_threshold(),
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

impl KeyGenerator {
    pub fn generate_keys(k: usize, n: usize, rng: &mut RNG, scheme: &ThresholdScheme, group: &Group, params: &Option<KeyParams>) -> Result<Vec<PrivateKey>, ThresholdCryptoError> {
        match scheme {
            ThresholdScheme::Bz03 => {
                if !group.supports_pairings() {
                    return Err(ThresholdCryptoError::CurveDoesNotSupportPairings);
                }

                let x = BigImpl::new_rand(&group, &group.get_order(), rng);
                let mut y = GroupElement::new_ecp2(&group);
                y.pow(&x);

                let (shares, h) = shamir_share(&x, k, n, rng);
                let mut private_keys = Vec::new();
                let public_key = Bz03PublicKey::new(&group, n, k, &y, &h );

                for i in 0..shares.len() {
                    private_keys.push(PrivateKey::Bz03(Bz03PrivateKey::new((i+1) as u16, &shares[i], &public_key)))
                }

                return Result::Ok(private_keys);
            },

            ThresholdScheme::Sg02 => {
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

                let x = BigImpl::new_rand(&group, &group.get_order(), rng);
                let mut y = GroupElement::new(&group);
                y.pow(&x);

                let (shares, h) = shamir_share(&x, k, n, rng);
                let mut private_keys = Vec::new();
                let public_key = Bls04PublicKey::new(&group, n, k, &y, &h );

                for i in 0..shares.len() {
                    private_keys.push(PrivateKey::Bls04(Bls04PrivateKey::new((i+1) as u16, &shares[i], &public_key)))
                }

                return Result::Ok(private_keys);
            },

            ThresholdScheme::Cks05 => {
                let x = BigImpl::new_rand(&group, &group.get_order(), rng);
                let mut y = GroupElement::new(&group);
                y.pow(&x);

                let (shares, h): (Vec<BigImpl>, Vec<GroupElement>) = shamir_share(&x, k as usize, n as usize, rng);
                let mut private_keys = Vec::new();

                let public_key = Cks05PublicKey::new(group, n, k, &y,&h );

                for i in 0..shares.len() {
                    private_keys.push(PrivateKey::Cks05(Cks05PrivateKey::new((i+1) as u16, &shares[i], &public_key)));
                }

                return Ok(private_keys);

            },

            ThresholdScheme::Frost => {
                todo!();
            },

            ThresholdScheme::Sh00 => {
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
                let pubkey = Sh00PublicKey::new(k as u16, N,  e.clone(), verificationKey, delta, modsize);
                
                let mut pks: Vec<PrivateKey> = Vec::new();
                for i in 0..n {
                    pks.push(PrivateKey::Sh00(Sh00PrivateKey::new(xi[i].0, m.clone(), xi[i].1.clone(), pubkey.clone())))
                }
                Ok(pks)
            }
        }
    }
}