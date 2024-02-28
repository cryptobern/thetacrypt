#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]

use asn1::{ParseError, WriteError};
use log::error;
use mcore::hash256::HASH256;
use theta_derive::DlShare;

use crate::integers::sizedint::SizedBigInt;
use crate::keys::keys::calc_key_id;
use crate::{
    dl_schemes::common::interpolate,
    groups::group::GroupElement,
    interface::{DlShare, SchemeError, Serializable, ThresholdSignatureParams},
    scheme_types_impl::GroupDetails,
};
use theta_proto::scheme_types::{Group, ThresholdScheme};
pub struct Bls04ThresholdSignature {
    g: GroupElement,
}

#[derive(Clone, Debug)]
pub struct Bls04PublicKey {
    id: String,
    group: Group,
    n: u16,
    k: u16,
    y: GroupElement,
    verification_key: Vec<GroupElement>,
}

impl Bls04PublicKey {
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

    pub fn get_key_id(&self) -> &str {
        &self.id
    }
}

impl PartialEq for Bls04PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n
            && self.k == other.k
            && self.y == other.y
            && self.verification_key.eq(&other.verification_key)
    }
}

impl Serializable for Bls04PublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.get_group().clone() as i32))?;
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
                let y = GroupElement::from_bytes(&b, &group, Option::None);

                let mut verification_key = Vec::new();

                for _i in 0..n {
                    b = d.read_element::<&[u8]>()?;
                    verification_key.push(GroupElement::from_bytes(&b, &group, Option::Some(0)));
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

#[derive(Clone, Debug, PartialEq)]
pub struct Bls04PrivateKey {
    id: u16,
    xi: SizedBigInt,
    pubkey: Bls04PublicKey,
}

impl Bls04PrivateKey {
    pub fn get_order(&self) -> SizedBigInt {
        self.pubkey.get_order()
    }

    pub fn get_share_id(&self) -> u16 {
        self.id
    }

    pub fn get_key_id(&self) -> &str {
        self.pubkey.get_key_id()
    }

    pub fn get_threshold(&self) -> u16 {
        self.pubkey.k
    }

    pub fn get_group(&self) -> &Group {
        self.pubkey.get_group()
    }

    pub fn new(id: u16, xi: &SizedBigInt, pubkey: &Bls04PublicKey) -> Self {
        Self {
            id: id.clone(),
            xi: xi.clone(),
            pubkey: pubkey.clone(),
        }
    }

    pub fn get_public_key(&self) -> Bls04PublicKey {
        self.pubkey.clone()
    }
}

impl Serializable for Bls04PrivateKey {
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
                let res = Bls04PublicKey::from_bytes(&pubbytes.to_vec());
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

#[derive(Clone, DlShare, PartialEq)]
pub struct Bls04SignatureShare {
    group: Group,
    id: u16,
    label: Vec<u8>,
    data: GroupElement, // ECP2
}

impl Bls04SignatureShare {
    pub fn get_label(&self) -> &[u8] {
        &self.label
    }
    pub fn get_scheme(&self) -> ThresholdScheme {
        ThresholdScheme::Bls04
    }
}

impl Serializable for Bls04SignatureShare {
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

#[derive(Clone, PartialEq, Debug)]
pub struct Bls04Signature {
    group: Group,
    sig: GroupElement, // ECP2
}

impl Bls04Signature {
    pub fn get_sig(&self) -> GroupElement {
        self.sig.clone()
    }
    pub fn get_group(&self) -> Group {
        self.group.clone()
    }
}

impl Serializable for Bls04Signature {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.get_group() as i32))?;
                w.write_element(&self.sig.to_bytes().as_slice())?;
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

                let bytes = d.read_element::<&[u8]>()?;
                let sig = GroupElement::from_bytes(&bytes, &group, Option::Some(1));

                return Ok(Self { group, sig });
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl Bls04ThresholdSignature {
    pub fn verify(
        sig: &Bls04Signature,
        pk: &Bls04PublicKey,
        msg: &[u8],
    ) -> Result<bool, SchemeError> {
        // TODO: Fix verification
        // R = signature_to_point(signature)
        // if R is invalid, return invalid
        // if signature_subgroup_check(R) is invalid, return invalid
        // if keyvalidate(pk) is invalid, return invalid

        GroupElement::ddh(
            &H(&msg, &pk.get_group()),
            &pk.y,
            &sig.sig,
            &GroupElement::new(&sig.get_group()),
        )
    }

    pub fn partial_sign(
        msg: &[u8],
        label: &[u8],
        sk: &Bls04PrivateKey,
        _params: &mut ThresholdSignatureParams,
    ) -> Bls04SignatureShare {
        let data = H(&msg, &sk.get_group()).pow(&sk.xi);

        Bls04SignatureShare {
            group: data.get_group().clone(),
            id: sk.id,
            label: label.to_vec(),
            data: data,
        }
    }

    pub fn verify_share(
        share: &Bls04SignatureShare,
        msg: &[u8],
        pk: &Bls04PublicKey,
    ) -> Result<bool, SchemeError> {
        GroupElement::ddh(
            &H(&msg, &share.get_group()),
            &pk.verification_key[(share.id - 1) as usize],
            &share.data,
            &GroupElement::new(&share.get_group()),
        )
    }

    pub fn assemble(
        shares: &Vec<Bls04SignatureShare>,
        msg: &[u8],
        _pk: &Bls04PublicKey,
    ) -> Bls04Signature {
        let sig = interpolate(&shares);
        Bls04Signature {
            group: sig.get_group().clone(),
            sig: sig,
        }
    }
}

fn H(m: &[u8], group: &Group) -> GroupElement {
    let q = group.get_order();

    let mut hash = HASH256::new();
    hash.process_array(&m);
    let h = hash.hash();

    let mut buf = Vec::new();
    buf = [&buf[..], &h].concat();

    let nbits = q.nbytes() * 8;

    if nbits > buf.len() * 4 {
        let mut g: [u8; 32];
        for i in 1..(((nbits - buf.len() * 4) / buf.len() * 8) as f64).ceil() as isize {
            g = h.clone();
            hash.process_array(&[&g[..], &(i.to_le_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    let mut res = SizedBigInt::from_bytes(&group, &buf);
    res.rmod(&group.get_order());

    GroupElement::new_pow_big_ecp2(&group, &res)
}
