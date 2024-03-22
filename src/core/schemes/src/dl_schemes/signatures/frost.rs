#![allow(non_snake_case)]

use std::cmp::Ordering;
use std::{collections::HashMap, hash::Hash};

use asn1::{ParseError, WriteError};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize};

use crate::groups::group::GroupOperations;
use crate::interface::ByteBufVisitor;
use crate::{
    dl_schemes::common::lagrange_coeff,
    groups::group::GroupElement,
    integers::{bigint::BigInt, sizedint::SizedBigInt},
    interface::{DlShare, SchemeError, Serializable},
    keys::keys::{calc_key_id, PublicKey},
    rand::{RngAlgorithm, RNG},
    scheme_types_impl::GroupDetails,
};
use log::{error, info};
use mcore::hash512::HASH512;
use theta_proto::scheme_types::{Group, ThresholdScheme};

const NUM_PRECOMPUTATIONS: usize = 10;

#[derive(Clone, Debug, PartialEq)]
pub struct FrostPublicKey {
    id: String,
    n: u16,
    k: u16,
    group: Group,
    y: GroupElement,
    h: Vec<GroupElement>,
}

impl FrostPublicKey {
    pub fn new(n: usize, k: usize, group: &Group, y: &GroupElement, h: &Vec<GroupElement>) -> Self {
        let mut k = Self {
            id: String::from(""),
            n: n as u16,
            k: k as u16,
            group: group.clone(),
            y: y.clone(),
            h: h.clone(),
        };

        let bytes = k.to_bytes().unwrap();
        let id = calc_key_id(&bytes);
        k.id = id;
        k
    }

    pub fn get_key_id(&self) -> &str {
        &self.id
    }

    pub fn get_group(&self) -> &Group {
        &self.group
    }

    pub fn get_verification_key(&self, id: u16) -> &GroupElement {
        &self.h[(id - 1) as usize]
    }

    pub fn get_n(&self) -> u16 {
        self.n
    }

    pub fn get_threshold(&self) -> u16 {
        self.k
    }
}

impl Serializable for FrostPublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.get_group().clone() as i32))?;
                w.write_element(&(self.n as u64))?;
                w.write_element(&(self.k as u64))?;
                w.write_element(&self.y.to_bytes().as_slice())?;

                for i in 0..self.h.len() {
                    w.write_element(&self.h[i].to_bytes().as_slice())?;
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
                let n = d.read_element::<u64>()? as u16;
                let k = d.read_element::<u64>()? as u16;

                if g.is_none() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault));
                }
                let group = g.unwrap();

                let mut b = d.read_element::<&[u8]>()?;
                let y = GroupElement::from_bytes(&b, &group, Option::None);

                let mut h = Vec::new();

                for _i in 0..n {
                    b = d.read_element::<&[u8]>()?;
                    h.push(GroupElement::from_bytes(&b, &group, Option::None));
                }

                Ok(Self {
                    id: calc_key_id(bytes),
                    n,
                    k,
                    group,
                    y,
                    h,
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

#[derive(Debug, Clone, PartialEq)]
pub struct FrostPrivateKey {
    id: u16,
    x: SizedBigInt,
    pubkey: FrostPublicKey,
}

impl FrostPrivateKey {
    pub fn new(id: usize, x: &SizedBigInt, pubkey: &FrostPublicKey) -> Self {
        Self {
            id: id as u16,
            x: x.clone(),
            pubkey: pubkey.clone(),
        }
    }

    pub fn get_share_id(&self) -> u16 {
        self.id
    }

    pub fn get_group(&self) -> &Group {
        self.pubkey.get_group()
    }

    pub fn get_threshold(&self) -> u16 {
        self.pubkey.get_threshold()
    }

    pub fn get_public_key(&self) -> &FrostPublicKey {
        &self.pubkey
    }

    pub fn get_key_id(&self) -> &str {
        self.pubkey.get_key_id()
    }
}

impl Serializable for FrostPrivateKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                w.write_element(&self.x.to_bytes().as_slice())?;

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
                let res = FrostPublicKey::from_bytes(&pubbytes.to_vec());
                if res.is_err() {
                    error!("Error deserializing frost public key");
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault {}));
                }

                let pubkey = res.unwrap();

                let x = SizedBigInt::from_bytes(&pubkey.get_group(), &bytes);

                return Ok(Self { id, x, pubkey });
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PublicCommitment {
    id: u16,
    pub(crate) hiding_nonce_commitment: GroupElement,
    pub(crate) binding_nonce_commitment: GroupElement,
}

impl PublicCommitment {
    pub fn get_id(&self) -> u16 {
        self.id
    }

    pub fn new(
        id: u16,
        hiding_nonce_commitment: GroupElement,
        binding_nonce_commitment: GroupElement,
    ) -> Self {
        Self {
            id,
            hiding_nonce_commitment,
            binding_nonce_commitment,
        }
    }
}

impl Ord for PublicCommitment {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialOrd for PublicCommitment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
 impl Eq for PublicCommitment{}

impl Serialize for PublicCommitment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes().unwrap();

        let mut seq = serializer.serialize_seq(Some(bytes.len()))?;
        for element in bytes {
            seq.serialize_element(&element)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for PublicCommitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let result = deserializer.deserialize_byte_buf(ByteBufVisitor); 
            match result {
                Ok(value) => {
                    let try_share = PublicCommitment::from_bytes(&value);
                    match try_share {
                        Ok(share) => Ok(share),
                        Err(e) => {
                            info!("{}", e.to_string());
                            Err(serde::de::Error::custom(format!("{}", e.to_string())))
                        },
                    }
                },
                Err(e) => {
                    info!("{}", e.to_string());
                    return Err(e)
                }
            }
    }
}

impl Serializable for PublicCommitment {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                w.write_element(&(self.hiding_nonce_commitment.get_group().clone() as i32))?;
                w.write_element(&self.hiding_nonce_commitment.to_bytes().as_slice())?;
                w.write_element(&self.binding_nonce_commitment.to_bytes().as_slice())?;
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

                let bytes = d.read_element::<&[u8]>()?;
                let hiding_nonce_commitment = GroupElement::from_bytes(bytes, &group, Option::None);
                let bytes = d.read_element::<&[u8]>()?;
                let binding_nonce_commitment =
                    GroupElement::from_bytes(bytes, &group, Option::None);

                return Ok(Self {
                    id,
                    hiding_nonce_commitment,
                    binding_nonce_commitment,
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

#[derive(PartialEq, Clone, Debug)]
pub struct Nonce {
    pub(crate) hiding_nonce: SizedBigInt,
    pub(crate) binding_nonce: SizedBigInt,
}

impl Serializable for Nonce {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.hiding_nonce.get_group().clone() as i32))?;
                w.write_element(&self.hiding_nonce.to_bytes().as_slice())?;
                w.write_element(&self.binding_nonce.to_bytes().as_slice())?;
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
                let hiding_nonce = SizedBigInt::from_bytes(&group, bytes);
                let bytes = d.read_element::<&[u8]>()?;
                let binding_nonce = SizedBigInt::from_bytes(&group, bytes);

                return Ok(Self {
                    hiding_nonce,
                    binding_nonce,
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

#[derive(Debug, Clone)]
pub struct BindingFactor {
    id: u16,
    factor: SizedBigInt,
}

#[derive(Debug, PartialEq, Clone)]
pub struct FrostSignatureShare {
    id: u16,
    data: SizedBigInt,
}

impl FrostSignatureShare {
    pub fn get_share(&self) -> SizedBigInt {
        self.data.clone()
    }

    // TODO: move label into share
    pub fn get_label(&self) -> &[u8] {
        todo!("not implemented");
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        ThresholdScheme::Frost
    }
}

impl DlShare for FrostSignatureShare {
    fn get_id(&self) -> u16 {
        self.id
    }

    // TODO: change data type
    fn get_data(&self) -> &GroupElement {
        todo!("wrong data type");
    }

    fn get_group(&self) -> &Group {
        self.data.get_group()
    }
}

impl Serialize for FrostSignatureShare {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes().unwrap();

        let mut seq = serializer.serialize_seq(Some(bytes.len()))?;
        for element in bytes {
            seq.serialize_element(&element)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for FrostSignatureShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let result = deserializer.deserialize_byte_buf(ByteBufVisitor); 
            match result {
                Ok(value) => {
                    let try_share = FrostSignatureShare::from_bytes(&value);
                    match try_share {
                        Ok(share) => Ok(share),
                        Err(e) => {
                            info!("{}", e.to_string());
                            Err(serde::de::Error::custom(format!("{}", e.to_string())))
                        },
                    }
                },
                Err(e) => {
                    info!("{}", e.to_string());
                    return Err(e)
                }
            }
    }
}

impl Serializable for FrostSignatureShare {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                w.write_element(&(self.data.get_group().clone() as i32))?;
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
                let bytes = d.read_element::<&[u8]>()?;
                let data = SizedBigInt::from_bytes(&group, &bytes);

                return Ok(Self { id, data });
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct FrostSignature {
    /* TODO: encode according to standard */
    R: GroupElement,
    z: SizedBigInt,
}

impl Serializable for FrostSignature {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.R.get_group().clone() as i32))?;
                w.write_element(&self.R.to_bytes().as_slice())?;
                w.write_element(&self.z.to_bytes().as_slice())?;
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
                //let label = d.read_element::<&[u8]>()?.to_vec()

                let bytes = d.read_element::<&[u8]>()?;
                let R = GroupElement::from_bytes(&bytes, &group, Option::None);

                let bytes = d.read_element::<&[u8]>()?;
                let z = SizedBigInt::from_bytes(&group, &bytes);

                return Ok(Self { R, z });
            });
        });

        if result.is_err() {
            println!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

#[derive(PartialEq, Clone, Debug)]
pub enum FrostOptions {
    PrecomputeOnly, // precompute commitments (execute round 1 NUM_PRECOMPUTATIONS times) and exit protocol
    Precomputation, // precompute commitments and use first commitment to generate signature in second round
    NoPrecomputation, // do not precompute commitments (might still use previously generated precomputations)
}

pub struct FrostState {}

pub fn partial_sign(
    nonce: &Nonce,
    commitment_list: &mut [PublicCommitment],
    message: &[u8],
    key: &FrostPrivateKey,
    node_id: u16,
) -> Result<(FrostSignatureShare, GroupElement), SchemeError> {
    let group = nonce.binding_nonce.get_group();
    let order = group.get_order();
    let pubkey = key.get_public_key();
    let binding_factor_list = compute_binding_factors(pubkey, commitment_list, message, group);

    let binding_factor = binding_factor_for_participant(&binding_factor_list, node_id);
    if binding_factor.is_err() {
        error!("binding factor error");
        return Err(binding_factor.expect_err(""));
    }

    let binding_factor = binding_factor.unwrap();
    let group_commitment = compute_group_commitment(commitment_list, &binding_factor_list, group);
    if group_commitment.is_err() {
        error!("group commitment error");
        return Err(group_commitment.expect_err(""));
    }

    let group_commitment = group_commitment.unwrap();

    let participant_list = participants_from_commitment_list(commitment_list);
    let lambda_i = lagrange_coeff(group, &participant_list, node_id as i32);
    let challenge = compute_challenge(&group_commitment, pubkey, message);

    let share = nonce
        .hiding_nonce
        .add(&nonce.binding_nonce.mul_mod(&binding_factor.factor, &order))
        .rmod(&order)
        .add(&lambda_i.mul_mod(&key.x, &order).mul_mod(&challenge, &order))
        .rmod(&order);

    Ok((
        FrostSignatureShare {
            id: node_id,
            data: share,
        },
        group_commitment,
    ))
}

pub fn commit(key: &FrostPrivateKey, rng: &mut RNG) -> (PublicCommitment, Nonce) {
    let hiding_nonce = nonce_generate(&key.x, rng);
    let binding_nonce = nonce_generate(&key.x, rng);
    let hiding_nonce_commitment = GroupElement::new_pow_big(key.get_group(), &hiding_nonce);
    let binding_nonce_commitment = GroupElement::new_pow_big(key.get_group(), &binding_nonce);
    let nonce = Nonce {
        hiding_nonce,
        binding_nonce,
    };
    let comm = PublicCommitment {
        id: key.get_share_id(),
        hiding_nonce_commitment,
        binding_nonce_commitment,
    };

    (comm, nonce)
}

pub fn assemble(
    group_commitment: &GroupElement,
    key: &FrostPrivateKey,
    shares: &Vec<FrostSignatureShare>,
) -> FrostSignature {
    let mut z = SizedBigInt::new_int(key.get_group(), 0);
    for i in 0..key.get_threshold() as usize {
        z = z
            .add(&shares[i].data)
            .rmod(&shares[i].data.get_group().get_order());
    }

    FrostSignature {
        R: group_commitment.clone(),
        z,
    }
}

pub fn verify_share(
    share: &FrostSignatureShare, //zi 
    pubkey: &FrostPublicKey, //Y
    message: &[u8], //M
    commitment_list: &mut [PublicCommitment], //(Dj, Ej)
    // share_commitment: PublicCommitment, //(Di, Ei)
) -> Result<bool, SchemeError> {
    let share_commitment = commitment_for_participant(commitment_list, share.get_id()).unwrap(); //TODO: handle unwrap
    // println!("Commitment of id {:?}: {:?}", share.get_id(), share_commitment);
    let binding_factor_list =
        compute_binding_factors(pubkey, commitment_list, message, pubkey.get_group()); //list of rho(s)
    let binding_factor = binding_factor_for_participant(&binding_factor_list, share.get_id());
    if binding_factor.is_err() {
        return Err(binding_factor.expect_err("Binding factor not found"));
    }

    let binding_factor = binding_factor.unwrap(); //rho of share i 
    
    let group_commitment =
        compute_group_commitment(commitment_list, &binding_factor_list, pubkey.get_group()); //this can also not be computed every time
    if group_commitment.is_err() {
        return Err(group_commitment.expect_err("Error in computing group commitment"));
    }

    let group_commitment = group_commitment.unwrap();

    let rcommitment_i = share_commitment.hiding_nonce_commitment.mul(
        &share_commitment
            .binding_nonce_commitment
            .pow(&binding_factor.factor),
    ); //commitment share of i => Ri
    
    
    // println!("Ri commitment of share {:?}: {:?}", share.get_id(), rcommitment_i);

    let challenge = compute_challenge(&group_commitment, pubkey, message);
    println!("challenge: {:?}", challenge);
    // println!("commitment_list {:?}", commitment_list);
    let participant_list = participants_from_commitment_list(commitment_list);
    let lambda_i = lagrange_coeff(
        &pubkey.get_group(),
        &participant_list,
        share.get_id() as i32,
    );

    let l = GroupElement::new_pow_big(pubkey.get_group(), &share.data);
    let r = rcommitment_i.mul(
        &pubkey
            .get_verification_key(share.get_id())
            .pow(&lambda_i.mul_mod(&challenge, &pubkey.get_group().get_order())),
    );
    
    Ok(l.eq(&r))
}


pub fn verify(signature: &FrostSignature, pk: &FrostPublicKey, msg: &[u8]) -> bool {
    let challenge = compute_challenge(&signature.R, pk, msg);

    let l = GroupElement::new_pow_big(&pk.get_group(), &signature.z);
    let r = signature.R.mul(&pk.y.pow(&challenge));
    l.eq(&r)
}

/*
impl Serializable for FrostData {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                match self {
                    Self::Commitment(rr) => {
                        w.write_element(&(1 as u64))?;

                        let bytes = rr.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }

                        w.write_element(&bytes.unwrap().as_slice())?;
                    }
                    Self::Share(rr) => {
                        w.write_element(&(2 as u64))?;

                        let bytes = rr.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }

                        w.write_element(&bytes.unwrap().as_slice())?;
                    }
                    Self::Precomputation(rr) => {
                        w.write_element(&(3 as u64))?;
                        w.write_element(&(rr.len() as u64))?;

                        for r in rr {
                            w.write_element(&r.to_bytes().unwrap().as_slice())?;
                        }
                    }
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
                let round = d.read_element::<u64>()? as u8;

                match round {
                    1 => {
                        let bytes = d.read_element::<&[u8]>()?.to_vec();
                        let a = PublicCommitment::from_bytes(&bytes);
                        if a.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::UnknownDefinedBy));
                        }

                        return Ok(Self::Commitment(a.unwrap()));
                    }
                    2 => {
                        let bytes = d.read_element::<&[u8]>()?.to_vec();
                        let b = FrostSignatureShare::from_bytes(&bytes);
                        if b.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::UnknownDefinedBy));
                        }

                        return Ok(Self::Share(b.unwrap()));
                    }
                    3 => {
                        let num = d.read_element::<u64>()?;
                        let mut commitments = Vec::new();
                        for _ in 0..num {
                            let bytes = d.read_element::<&[u8]>()?.to_vec();
                            let comm = PublicCommitment::from_bytes(&bytes).unwrap();
                            commitments.push(comm);
                        }
                        return Ok(Self::Precomputation(commitments));
                    }
                    _ => {
                        return Err(ParseError::new(asn1::ParseErrorKind::UnknownDefinedBy));
                    }
                }
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}*/

pub(crate) fn nonce_generate(secret: &SizedBigInt, rng: &mut RNG) -> SizedBigInt {
    let random_bytes = rng.random_bytes(32);
    println!("rand bytes {}", hex::encode(&random_bytes));
    let secret_bytes = serialize_scalar(secret);

    println!("secret bytes {}", hex::encode(&secret_bytes));
    return h3(&[random_bytes, secret_bytes].concat(), &secret.get_group());
}

pub(crate) fn compute_binding_factors(
    pubkey: &FrostPublicKey,
    commitment_list: &mut [PublicCommitment],
    msg: &[u8],
    group: &Group,
) -> Vec<BindingFactor> {
    let pubkey_enc = &*pubkey.y.to_bytes();
    let msg_hash = h4(msg, group);
    commitment_list.sort();
    let encoded_commitment_hash = h5(&encode_group_commitment_list(commitment_list), group);
    let rho_input_prefix = [pubkey_enc, &msg_hash, &encoded_commitment_hash].concat(); //TODO: check if here the pubkey should be changed for the index as in the paper, otherwise this value is the same for all

    let mut binding_factor_list: Vec<BindingFactor> = Vec::new();
    for i in 0..commitment_list.len() {
        let rho_input = [
            rho_input_prefix.clone(),
            encode_uint16(commitment_list[i].id),
        ]
        .concat();
        let binding_factor = h1(&rho_input, group);
        binding_factor_list.push(BindingFactor {
            id: commitment_list[i].id,
            factor: binding_factor,
        });
    }

    return binding_factor_list;
}

pub(crate) fn compute_group_commitment(
    commitment_list: &[PublicCommitment],
    binding_factor_list: &Vec<BindingFactor>,
    group: &Group,
) -> Result<GroupElement, SchemeError> {
    let mut group_commitment = GroupElement::identity(group);
    for i in 0..commitment_list.len() {
        let binding_factor;
        if let Ok(factor) =
            binding_factor_for_participant(binding_factor_list, commitment_list[i].id) //checks that we have the binding_factor for a certain id present in the commitment list
        {
            binding_factor = factor.factor;
        } else {
            return Err(SchemeError::IdNotFound);
        }

        let binding_commitment = commitment_list[i]
            .binding_nonce_commitment
            .pow(&binding_factor); //Ei^rho(i)
        group_commitment = group_commitment
            .mul(&commitment_list[i].hiding_nonce_commitment)
            .mul(&binding_commitment); //Di*(Ei^rho(i))
    }

    Ok(group_commitment)
}

fn compute_challenge(
    group_commitment: &GroupElement,
    pk: &FrostPublicKey,
    msg: &[u8],
) -> SizedBigInt {
    let group_comm_enc = group_commitment.to_bytes();
    let group_public_key_enc = pk.y.to_bytes();
    let challenge_input = [group_comm_enc, group_public_key_enc, msg.to_vec()].concat();
    h2(&challenge_input, &pk.get_group())
}

fn encode_group_commitment_list(commitment_list: &[PublicCommitment]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for i in 0..commitment_list.len() {
        let enc_comm = [
            encode_uint16(commitment_list[i].id),
            commitment_list[i].hiding_nonce_commitment.to_bytes(),
            commitment_list[i].binding_nonce_commitment.to_bytes(),
        ]
        .concat();
        encoded = [encoded, enc_comm].concat();
    }

    encoded
}

fn binding_factor_for_participant(
    binding_factor_list: &Vec<BindingFactor>,
    identifier: u16,
) -> Result<BindingFactor, SchemeError> {
    for i in 0..binding_factor_list.len() {
        if identifier as u16 == binding_factor_list[i].id {
            return Ok(binding_factor_list[i].clone());
        }
    }

    Err(SchemeError::IdNotFound)
}

fn commitment_for_participant(
    commitment_list: &[PublicCommitment],
    identifier: u16,
) -> Result<PublicCommitment, SchemeError> {
    for i in 0..commitment_list.len() {
        if identifier as u16 == commitment_list[i].id {
            return Ok(commitment_list[i].clone());
        }
    }

    Err(SchemeError::IdNotFound)
}


fn participants_from_commitment_list(commitment_list: &[PublicCommitment]) -> Vec<u16> {
    let mut identifiers = Vec::new();

    for i in 0..commitment_list.len() {
        identifiers.push(commitment_list[i].id);
    }

    identifiers
}

fn encode_uint16(val: u16) -> Vec<u8> {
    val.to_be_bytes().to_vec()
}

fn h1(bytes: &[u8], group: &Group) -> SizedBigInt {
    // TODO: implement for other ciphersuites
    let msg = [get_context_string(group).unwrap(), b"rho", bytes].concat();
    let mut hash = HASH512::new();
    hash.process_array(&msg);
    let h = hash.hash();
    let res = SizedBigInt::from_bytes(group, &h);
    res.rmod(&group.get_order())
}

fn h2(bytes: &[u8], group: &Group) -> SizedBigInt {
    // TODO: implement for other ciphersuites
    let mut hash = HASH512::new();
    hash.process_array(&bytes);
    let h = hash.hash();
    let res = SizedBigInt::from_bytes(group, &h);
    res.rmod(&group.get_order())
}

fn h3(bytes: &[u8], group: &Group) -> SizedBigInt {
    // TODO: implement for other ciphersuites
    let msg = [get_context_string(group).unwrap(), b"nonce", bytes].concat();
    let mut hash = HASH512::new();
    hash.process_array(&msg);
    let h = hash.hash();

    let mod_bytes =
        hex::decode("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED").unwrap();
    let modulo = BigInt::from_bytes(&mod_bytes);
    let r = BigInt::from_bytes(&h)
        .rmod(&modulo)
        .to_sized_bytes(32)
        .unwrap();

    SizedBigInt::from_bytes(group, &r)
}

/*
-   SerializeScalar(s): Implemented by outputting the little-endian
    32-byte encoding of the Scalar value with the top three bits
    set to zero.

-   DeserializeScalar(buf): Implemented by attempting to
    deserialize a Scalar from a little-endian 32-byte string.  This
    function can fail if the input does not represent a Scalar in
    the range [0, G.Order() - 1].  Note that this means the top
    three bits of the input MUST be zero. */

fn h4(bytes: &[u8], group: &Group) -> [u8; 64] {
    // TODO: implement for other ciphersuites
    let msg = [get_context_string(group).unwrap(), b"msg", bytes].concat();
    let mut hash = HASH512::new();
    hash.process_array(&msg);
    hash.hash()
}

fn h5(bytes: &[u8], group: &Group) -> [u8; 64] {
    // TODO: implement for other ciphersuites
    let msg = [get_context_string(group).unwrap(), b"com", bytes].concat();
    let mut hash = HASH512::new();
    hash.process_array(&msg);
    hash.hash()
}

fn get_context_string(group: &Group) -> Result<&[u8], SchemeError> {
    match group {
        Group::Ed25519 => return Ok(b"FROST-ED25519-SHA512-v1"),
        _ => return Err(SchemeError::IncompatibleGroup),
    }
}

pub(crate) fn serialize_scalar(scalar: &SizedBigInt) -> Vec<u8> {
    // only for ed25519 sha512
    let mut bytes = scalar.to_bytes();
    bytes.reverse();
    let idx = bytes.len() - 1;
    bytes[idx] &= 0x1f;
    bytes
}

pub(crate) fn deserialize_scalar(group: &Group, bytes: &[u8]) -> SizedBigInt {
    let mut b = bytes.to_vec();
    b.reverse();
    SizedBigInt::from_bytes(group, &b)
}
