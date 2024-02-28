#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use asn1::{ParseError, WriteError};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use derive::DlShare;
use log::error;
use mcore::bls12381::big;
use mcore::hash256::*;
use rasn::AsnType;

use crate::dl_schemes::bigint::SizedBigInt;
use crate::dl_schemes::common::*;
use crate::group::GroupElement;
use crate::interface::{DlShare, SchemeError, Serializable, ThresholdCipherParams};
use crate::keys::keys::calc_key_id;
use crate::scheme_types_impl::GroupDetails;
use theta_proto::scheme_types::{Group, ThresholdScheme};

#[derive(Clone, Debug, AsnType)]
pub struct Bz03PublicKey {
    id: String,
    n: u16,
    k: u16,
    group: Group,
    y: GroupElement, //ECP2
    verification_key: Vec<GroupElement>,
}

impl Bz03PublicKey {
    pub fn new(
        group: &Group,
        n: usize,
        k: usize,
        y: &GroupElement,
        verification_key: &Vec<GroupElement>,
    ) -> Self {
        let mut k = Self {
            id: String::from(""),
            group: group.clone(),
            n: n as u16,
            k: k as u16,
            y: y.clone(),
            verification_key: verification_key.clone(),
        };

        let bytes = k.to_bytes().unwrap();
        let id = calc_key_id(&bytes);
        k.id = id;
        k
    }

    pub fn get_key_id(&self) -> &str {
        &self.id
    }

    pub fn get_order(&self) -> SizedBigInt {
        self.y.get_order()
    }

    pub fn get_group(&self) -> &Group {
        &self.group
    }

    pub fn get_threshold(&self) -> u16 {
        self.k
    }

    pub fn get_n(&self) -> u16 {
        self.n
    }
}

impl Serializable for Bz03PublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(*self.get_group() as i32))?;
                w.write_element(&(self.n as u64))?;
                w.write_element(&(self.k as u64))?;
                w.write_element(&self.y.to_bytes().as_slice())?;

                for i in 0..self.verification_key.len() {
                    w.write_element(&self.verification_key[i].to_bytes().as_slice())?;
                }
                Ok(())
            }))
        });

        if result.is_err() {
            return Err(SchemeError::SerializationFailed);
        }

        Ok(result.unwrap())
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let g = Group::from_i32(d.read_element::<i32>()?);
                if g.is_none() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault));
                }
                let group = g.unwrap();
                let n = d.read_element::<u64>()? as u16;
                let k = d.read_element::<u64>()? as u16;

                let mut b = d.read_element::<&[u8]>()?;
                let y = GroupElement::from_bytes(&b, &group, Option::Some(1));

                let mut verification_key = Vec::new();

                for _i in 0..n {
                    b = d.read_element::<&[u8]>()?;
                    verification_key.push(GroupElement::from_bytes(&b, &group, Option::None));
                }

                Ok(Self {
                    id: calc_key_id(bytes),
                    n,
                    k,
                    group,
                    y,
                    verification_key,
                })
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl PartialEq for Bz03PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.y.eq(&other.y) && self.verification_key.eq(&other.verification_key)
    }
}

#[derive(Clone, Debug, AsnType)]
pub struct Bz03PrivateKey {
    id: u16,
    xi: SizedBigInt,
    pubkey: Bz03PublicKey,
}

impl Bz03PrivateKey {
    pub fn new(id: u16, xi: &SizedBigInt, pubkey: &Bz03PublicKey) -> Self {
        Self {
            id,
            xi: xi.clone(),
            pubkey: pubkey.clone(),
        }
    }

    pub fn get_public_key(&self) -> &Bz03PublicKey {
        &self.pubkey
    }

    pub fn get_order(&self) -> SizedBigInt {
        self.get_group().get_order()
    }

    pub fn get_group(&self) -> &Group {
        self.pubkey.get_group()
    }

    pub fn get_threshold(&self) -> u16 {
        self.pubkey.get_threshold()
    }

    pub fn get_n(&self) -> u16 {
        self.pubkey.get_n()
    }

    pub fn get_share_id(&self) -> u16 {
        self.id
    }

    pub fn get_key_id(&self) -> &str {
        self.get_public_key().get_key_id()
    }
}

impl Serializable for Bz03PrivateKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                w.write_element(&self.xi.to_bytes().as_slice())?;

                let bytes = self.pubkey.to_bytes();
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

        Ok(result.unwrap())
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let id = d.read_element::<u64>()? as u16;

                let bytes = d.read_element::<&[u8]>()?;
                let pubbytes = d.read_element::<&[u8]>()?;
                let res = Bz03PublicKey::from_bytes(&pubbytes.to_vec());
                if res.is_err() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault {}));
                }

                let pubkey = res.unwrap();

                let xi = SizedBigInt::from_bytes(&pubkey.get_group(), &bytes);

                return Ok(Self { id, xi, pubkey });
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl PartialEq for Bz03PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.xi == other.xi && self.pubkey == other.pubkey
    }
}

#[derive(Clone, AsnType, DlShare)]
pub struct Bz03DecryptionShare {
    group: Group,
    id: u16,
    data: GroupElement,
    label: Vec<u8>,
}

impl Bz03DecryptionShare {
    pub fn get_scheme(&self) -> ThresholdScheme {
        ThresholdScheme::Bz03
    }

    pub fn get_label(&self) -> &[u8] {
        &self.label
    }
}

impl Serializable for Bz03DecryptionShare {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                w.write_element(&(self.get_group().clone() as i32))?;
                w.write_element(&self.label.as_slice())?;
                w.write_element(&self.data.to_bytes().as_slice())?;
                Ok(())
            }))
        });

        if result.is_err() {
            return Err(SchemeError::SerializationFailed);
        }

        Ok(result.unwrap())
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let id = d.read_element::<u64>()? as u16;
                let g = Group::from_i32(d.read_element::<i32>()?);
                if g.is_none() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault));
                }
                let group = g.unwrap();
                let label = d.read_element::<&[u8]>()?.to_vec();

                let bytes = d.read_element::<&[u8]>()?;
                let data = GroupElement::from_bytes(&bytes, &group, Option::Some(1));

                return Ok(Self {
                    id,
                    group,
                    label,
                    data,
                });
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl PartialEq for Bz03DecryptionShare {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.data == other.data
    }
}

#[derive(Clone, AsnType, Debug)]
pub struct Bz03Ciphertext {
    label: Vec<u8>,
    ctxt: Vec<u8>,
    c_k: Vec<u8>,
    u: GroupElement, //ECP2
    hr: GroupElement,
    key_id: String,
}

impl Bz03Ciphertext {
    pub fn get_ctxt(&self) -> &[u8] {
        &self.ctxt
    }
    pub fn get_ck(&self) -> &[u8] {
        &self.c_k
    }
    pub fn get_label(&self) -> &[u8] {
        &self.label
    }
    pub fn get_scheme(&self) -> ThresholdScheme {
        ThresholdScheme::Sg02
    }
    pub fn get_group(&self) -> &Group {
        self.u.get_group()
    }
    pub fn get_key_id(&self) -> &str {
        &self.key_id
    }
}

impl Serializable for Bz03Ciphertext {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.get_group().clone() as i32))?;
                w.write_element(&self.label.as_slice())?;
                w.write_element(&self.ctxt.as_slice())?;
                w.write_element(&self.u.to_bytes().as_slice())?;
                w.write_element(&self.hr.to_bytes().as_slice())?;
                w.write_element(&self.c_k.as_slice())?;
                w.write_element(&self.key_id.as_bytes())?;

                Ok(())
            }))
        });

        if result.is_err() {
            return Err(SchemeError::SerializationFailed);
        }

        Ok(result.unwrap())
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let g = Group::from_i32(d.read_element::<i32>()?);
                if g.is_none() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault));
                }
                let group = g.unwrap();
                let label = d.read_element::<&[u8]>()?.to_vec();
                let msg = d.read_element::<&[u8]>()?.to_vec();

                let mut b = d.read_element::<&[u8]>()?;
                let u = GroupElement::from_bytes(&b, &group, Option::Some(1));

                b = d.read_element::<&[u8]>()?;
                let hr = GroupElement::from_bytes(&b, &group, Option::Some(0));

                let c_k = d.read_element::<&[u8]>()?.to_vec();

                let key_id = String::from_utf8(d.read_element::<&[u8]>()?.to_vec());
                if key_id.is_err() {
                    return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                }

                let key_id = key_id.unwrap();

                return Ok(Self {
                    label,
                    ctxt: msg,
                    u,
                    c_k,
                    hr,
                    key_id,
                });
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl PartialEq for Bz03Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        self.label == other.label
            && self.ctxt == other.ctxt
            && self.c_k == other.c_k
            && self.u == other.u
            && self.hr == other.hr
    }
}

pub struct Bz03ThresholdCipher {
    g: u8,
}

pub struct Bz03Params {}

impl Bz03ThresholdCipher {
    pub fn encrypt(
        msg: &[u8],
        label: &[u8],
        pk: &Bz03PublicKey,
        params: &mut ThresholdCipherParams,
    ) -> Bz03Ciphertext {
        let r = SizedBigInt::new_rand(
            &pk.get_group(),
            &pk.get_group().get_order(),
            &mut params.rng,
        );
        let u = GroupElement::new_ecp2(&pk.get_group()).pow(&r);

        let rY = pk.y.pow(&r);

        let k = gen_symm_key(&mut params.rng);
        let key = Key::from_slice(&k);
        let cipher = ChaCha20Poly1305::new(key);
        let encryption: Vec<u8> = cipher
            .encrypt(Nonce::from_slice(&rY.to_bytes()[0..12]), msg)
            .expect("encryption failure");

        let c_k = xor(g(&rY), (k).to_vec());

        let hr = h(&u, &c_k).pow(&r);

        let c = Bz03Ciphertext {
            label: label.to_vec(),
            ctxt: encryption,
            c_k: c_k.to_vec(),
            u: u,
            hr: hr,
            key_id: pk.id.clone(),
        };
        c
    }

    pub fn verify_ciphertext(
        ct: &Bz03Ciphertext,
        _pk: &Bz03PublicKey,
    ) -> Result<bool, SchemeError> {
        let h = h(&ct.u, &ct.c_k);

        GroupElement::ddh(
            &ct.u,
            &h,
            &GroupElement::new_ecp2(&ct.u.get_group()),
            &ct.hr,
        )
    }

    pub fn verify_share(
        share: &Bz03DecryptionShare,
        ct: &Bz03Ciphertext,
        pk: &Bz03PublicKey,
    ) -> Result<bool, SchemeError> {
        GroupElement::ddh(
            &share.data,
            &GroupElement::new(&share.group),
            &ct.u,
            &pk.verification_key[(&share.id - 1) as usize],
        )
    }

    pub fn partial_decrypt(
        ct: &Bz03Ciphertext,
        sk: &Bz03PrivateKey,
        _params: &mut ThresholdCipherParams,
    ) -> Bz03DecryptionShare {
        let data = ct.u.pow(&sk.xi);

        Bz03DecryptionShare {
            group: data.get_group().clone(),
            label: ct.label.clone(),
            id: sk.id,
            data,
        }
    }

    pub fn assemble(
        shares: &Vec<Bz03DecryptionShare>,
        ct: &Bz03Ciphertext,
    ) -> Result<Vec<u8>, SchemeError> {
        let rY = interpolate(shares);

        let k = xor(g(&rY), ct.c_k.clone());
        let key = Key::from_slice(&k);
        let cipher = ChaCha20Poly1305::new(key);
        let msg = cipher.decrypt(Nonce::from_slice(&rY.to_bytes()[0..12]), ct.ctxt.as_ref());

        if msg.is_err() {
            return Err(SchemeError::MacFailure);
        }

        Ok(msg.unwrap())
    }
}

fn h(g: &GroupElement, m: &Vec<u8>) -> GroupElement {
    let bytes = g.to_bytes();

    let mut h = HASH256::new();
    h.process_array(&[&bytes[..], &m[..]].concat());

    let h = [&vec![0; big::MODBYTES - 32][..], &h.hash()[..]].concat();

    let s = SizedBigInt::from_bytes(&g.get_group(), &h).rmod(&g.get_group().get_order());

    GroupElement::new(&g.get_group()).pow(&s)
}

// hash ECP to bit string
fn g(x: &GroupElement) -> Vec<u8> {
    let res = x.to_bytes();

    let mut h = HASH256::new();
    h.process_array(&res);

    let r = h.hash().to_vec();
    r
}
