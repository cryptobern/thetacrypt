#![allow(non_snake_case)]

use asn1::{ParseError, WriteError};

use crate::{
    dl_schemes::{bigint::BigImpl, common::lagrange_coeff},
    group::GroupElement,
    interface::{DlShare, SchemeError, Serializable},
    keys::keys::calc_key_id,
    rand::{RngAlgorithm, RNG},
    scheme_types_impl::GroupDetails,
};
use log::error;
use mcore::hash512::HASH512;
use theta_proto::scheme_types::{Group, ThresholdScheme};

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
    x: BigImpl,
    pubkey: FrostPublicKey,
}

impl FrostPrivateKey {
    pub fn new(id: usize, x: &BigImpl, pubkey: &FrostPublicKey) -> Self {
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

                let x = BigImpl::from_bytes(&pubkey.get_group(), &bytes);

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
    hiding_nonce_commitment: GroupElement,
    binding_nonce_commitment: GroupElement,
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
    hiding_nonce: BigImpl,
    binding_nonce: BigImpl,
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
                let hiding_nonce = BigImpl::from_bytes(&group, bytes);
                let bytes = d.read_element::<&[u8]>()?;
                let binding_nonce = BigImpl::from_bytes(&group, bytes);

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
    factor: BigImpl,
}

#[derive(Debug, PartialEq, Clone)]
pub struct FrostSignatureShare {
    id: u16,
    data: BigImpl,
}

impl FrostSignatureShare {
    pub fn get_share(&self) -> BigImpl {
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
                let data = BigImpl::from_bytes(&group, &bytes);

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
    z: BigImpl,
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
                let z = BigImpl::from_bytes(&group, &bytes);

                return Ok(Self { R, z });
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
pub struct FrostThresholdSignature {
    round: u8,
    key: FrostPrivateKey,
    label: Vec<u8>,
    msg: Option<Vec<u8>>,
    nonce: Option<Nonce>,
    commitment: Option<PublicCommitment>,
    commitment_list: Vec<PublicCommitment>,
    group_commitment: Option<GroupElement>,
    share: Option<FrostSignatureShare>,
    shares: Vec<FrostSignatureShare>,
    signature: Option<FrostSignature>,
    finished: bool,
}

impl<'a> FrostThresholdSignature {
    pub fn new(key: &FrostPrivateKey) -> Self {
        Self {
            round: 0,
            msg: None,
            label: Vec::new(),
            shares: Vec::new(),
            key: key.clone(),
            nonce: Option::None,
            commitment: Option::None,
            commitment_list: Vec::new(),
            group_commitment: None,
            share: None,
            finished: false,
            signature: Option::None,
        }
    }

    pub fn set_label(&mut self, label: &[u8]) {
        self.label = label.to_vec();
    }

    pub fn get_label(&self) -> Vec<u8> {
        return self.label.clone();
    }

    pub fn set_commitment(&mut self, comm: &PublicCommitment) {
        self.commitment = Some(comm.clone());
    }

    pub fn set_msg(&mut self, msg: &'a [u8]) -> Result<(), SchemeError> {
        if self.msg.is_some() {
            return Err(SchemeError::MessageAlreadySpecified);
        }
        self.msg = Some(msg.to_vec());
        Ok(())
    }

    pub fn update(&mut self, round_result: &FrostRoundResult) -> Result<(), SchemeError> {
        match round_result {
            FrostRoundResult::RoundOne(result) => {
                self.commitment_list.push(result.clone());
                Ok(())
            }
            FrostRoundResult::RoundTwo(share) => {
                let result = self.verify_share(share);
                if result.is_err() {
                    return Err(result.unwrap_err());
                }

                self.shares.push(share.clone());

                if self.shares.len() == self.key.get_threshold() as usize {
                    let sig = self.assemble();
                    if sig.is_err() {
                        return Err(sig.unwrap_err());
                    }

                    self.signature = Some(sig.unwrap());
                }

                Ok(())
            }
        }
    }

    pub fn is_ready_for_next_round(&self) -> bool {
        match self.round {
            1 => {
                if self.commitment_list.len() >= self.key.get_threshold() as usize {
                    return true;
                }
                return false;
            }
            2 => {
                if self.shares.len() >= self.key.get_threshold() as usize {
                    return true;
                }
                return false;
            }
            _ => return false,
        }
    }

    pub fn get_signature(&self) -> Result<FrostSignature, SchemeError> {
        if self.signature.is_none() {
            return Err(SchemeError::ProtocolNotFinished);
        }

        Ok(self.signature.clone().unwrap())
    }

    pub fn is_finished(&self) -> bool {
        self.round == 2 && self.signature.is_some()
    }

    pub fn do_round(&mut self) -> Result<FrostRoundResult, SchemeError> {
        if self.round == 0 {
            let res = self.commit(&mut RNG::new(RngAlgorithm::OsRng));
            if res.is_ok() {
                self.round += 1;
                return Ok(res.unwrap());
            }

            return Err(res.unwrap_err());
        } else if self.round == 1 {
            let res = self.partial_sign();
            if res.is_ok() {
                self.round += 1;
                return Ok(res.unwrap());
            }

            return Err(res.unwrap_err());
        }

        Err(SchemeError::InvalidRound)
    }

    fn partial_sign(&mut self) -> Result<FrostRoundResult, SchemeError> {
        let group = self.key.get_group();
        let order = group.get_order();

        if self.get_nonce().is_none() {
            error!("No nonce set");
            return Err(SchemeError::PreviousRoundNotExecuted);
        }

        if self.msg.is_none() {
            error!("Message not set");
            return Err(SchemeError::MessageNotSpecified);
        }

        let msg = self.msg.as_ref().unwrap();

        let nonce = self.get_nonce().as_ref().unwrap();
        let commitment_list = self.get_commitment_list();

        let binding_factor_list = compute_binding_factors(
            &self.key.pubkey,
            commitment_list,
            msg,
            &self.key.get_group(),
        );

        let binding_factor = binding_factor_for_participant(&binding_factor_list, self.key.id);
        if binding_factor.is_err() {
            error!("binding factor error");
            return Err(binding_factor.expect_err(""));
        }

        let binding_factor = binding_factor.unwrap();
        let group_commitment =
            compute_group_commitment(commitment_list, &binding_factor_list, &self.key.get_group());
        if group_commitment.is_err() {
            error!("group commitment error");
            return Err(group_commitment.expect_err(""));
        }

        let group_commitment = group_commitment.unwrap();

        let participant_list = participants_from_commitment_list(commitment_list);
        let lambda_i = lagrange_coeff(&group, &participant_list, self.key.get_share_id() as i32);
        let challenge = compute_challenge(&group_commitment, &self.key.get_public_key(), msg);

        let share = nonce
            .hiding_nonce
            .add(&nonce.binding_nonce.mul_mod(&binding_factor.factor, &order))
            .rmod(&order)
            .add(
                &lambda_i
                    .mul_mod(&self.key.x, &order)
                    .mul_mod(&challenge, &order),
            )
            .rmod(&order);

        //self.commitment_list = commitment_list.to_vec();
        self.group_commitment = Option::Some(group_commitment);

        Ok(FrostRoundResult::RoundTwo(FrostSignatureShare {
            id: self.key.get_share_id(),
            data: share,
        }))
    }

    fn commit(&mut self, rng: &mut RNG) -> Result<FrostRoundResult, SchemeError> {
        let hiding_nonce = nonce_generate(&self.key.x, rng);
        let binding_nonce = nonce_generate(&self.key.x, rng);
        let hiding_nonce_commitment =
            GroupElement::new_pow_big(&self.key.get_group(), &hiding_nonce);
        let binding_nonce_commitment =
            GroupElement::new_pow_big(&self.key.get_group(), &binding_nonce);
        let nonce = Nonce {
            hiding_nonce,
            binding_nonce,
        };
        let comm = PublicCommitment {
            id: self.key.get_share_id(),
            hiding_nonce_commitment,
            binding_nonce_commitment,
        };

        //FrostThresholdSignature { nonce, commitment:comm, commitment_list:Vec::new(), group_commitment:Option::None, share:Option::None }
        self.commitment = Some(comm.clone());
        self.nonce = Some(nonce.clone());

        Ok(FrostRoundResult::RoundOne(comm))
    }

    fn assemble(&self) -> Result<FrostSignature, SchemeError> {
        let group_commitment;
        if let Some(group_commit) = &self.group_commitment {
            group_commitment = group_commit;
        } else {
            return Err(SchemeError::WrongState);
        }

        let mut z = BigImpl::new_int(&group_commitment.get_group(), 0);
        for i in 0..self.shares.len() {
            z = z
                .add(&self.shares[i].data)
                .rmod(&self.shares[i].data.get_group().get_order());
        }

        Ok(FrostSignature {
            R: group_commitment.clone(),
            z,
        })
    }

    fn verify_share(&self, share: &FrostSignatureShare) -> Result<bool, SchemeError> {
        let commitment_list = self.get_commitment_list();
        let pk = &self.key.pubkey;
        let msg = self.msg.as_ref().unwrap();
        if self.get_commitment().is_none() {
            return Err(SchemeError::PreviousRoundNotExecuted);
        }

        if self.msg.is_none() {
            return Err(SchemeError::MessageNotSpecified);
        }

        let commitment = commitment_for_participant(&self.commitment_list, share.get_id());
        if commitment.is_err() {
            return Err(commitment.expect_err(""));
        }
        let commitment = commitment.unwrap();

        let binding_factor_list = compute_binding_factors(
            &self.key.pubkey,
            &commitment_list,
            msg,
            &self.key.get_group(),
        );
        let binding_factor = binding_factor_for_participant(&binding_factor_list, share.get_id());
        if binding_factor.is_err() {
            return Err(binding_factor.expect_err(""));
        }

        let binding_factor = binding_factor.unwrap();
        let group_commitment =
            compute_group_commitment(commitment_list, &binding_factor_list, &pk.get_group());
        if group_commitment.is_err() {
            return Err(group_commitment.expect_err(""));
        }

        let group_commitment = group_commitment.unwrap();

        let comm_share = commitment.hiding_nonce_commitment.mul(
            &commitment
                .binding_nonce_commitment
                .pow(&binding_factor.factor),
        );

        let challenge = compute_challenge(&group_commitment, pk, msg);
        let participant_list = participants_from_commitment_list(commitment_list);
        let lambda_i = lagrange_coeff(&pk.get_group(), &participant_list, share.get_id() as i32);

        let l = GroupElement::new_pow_big(&pk.get_group(), &share.data);
        let r = comm_share.mul(
            &pk.get_verification_key(share.get_id())
                .pow(&lambda_i.mul_mod(&challenge, &pk.get_group().get_order())),
        );

        Ok(l.eq(&r))
    }

    fn get_nonce(&self) -> &Option<Nonce> {
        &self.nonce
    }

    fn get_commitment(&self) -> &Option<PublicCommitment> {
        &self.commitment
    }

    fn get_commitment_list(&self) -> &Vec<PublicCommitment> {
        &self.commitment_list
    }

    pub fn verify(signature: &FrostSignature, pk: &FrostPublicKey, msg: &[u8]) -> bool {
        let challenge = compute_challenge(&signature.R, pk, msg);

        let l = GroupElement::new_pow_big(&pk.get_group(), &signature.z);
        let r = signature.R.mul(&pk.y.pow(&challenge));
        l.eq(&r)
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone)]
pub enum FrostRoundResult {
    RoundOne(PublicCommitment),
    RoundTwo(FrostSignatureShare),
}

impl Serializable for FrostRoundResult {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                match self {
                    Self::RoundOne(rr) => {
                        w.write_element(&(1 as u64))?;

                        let bytes = rr.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }

                        w.write_element(&bytes.unwrap().as_slice())?;
                    }
                    Self::RoundTwo(rr) => {
                        w.write_element(&(2 as u64))?;

                        let bytes = rr.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }

                        w.write_element(&bytes.unwrap().as_slice())?;
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

                        return Ok(Self::RoundOne(a.unwrap()));
                    }
                    2 => {
                        let bytes = d.read_element::<&[u8]>()?.to_vec();
                        let b = FrostSignatureShare::from_bytes(&bytes);
                        if b.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::UnknownDefinedBy));
                        }

                        return Ok(Self::RoundTwo(b.unwrap()));
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
}

pub fn get_share(instance: &FrostThresholdSignature) -> Result<FrostSignatureShare, SchemeError> {
    if instance.share.is_none() {
        return Err(SchemeError::WrongState);
    }

    Ok(instance.share.clone().unwrap())
}

fn nonce_generate(secret: &BigImpl, rng: &mut RNG) -> BigImpl {
    let k_enc = rng.random_bytes(32);
    let secret_enc = secret.to_bytes();
    return h3(&[k_enc, secret_enc].concat(), &secret.get_group());
}

fn compute_binding_factors(
    pubkey: &FrostPublicKey,
    commitment_list: &[PublicCommitment],
    msg: &[u8],
    group: &Group,
) -> Vec<BindingFactor> {
    let pubkey_enc = &*pubkey.y.to_bytes();
    let msg_hash = h4(msg, group);
    let encoded_commitment_hash = h5(&encode_group_commitment_list(commitment_list), group);
    let rho_input_prefix = [pubkey_enc, &msg_hash, &encoded_commitment_hash].concat();

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

fn compute_group_commitment(
    commitment_list: &[PublicCommitment],
    binding_factor_list: &Vec<BindingFactor>,
    group: &Group,
) -> Result<GroupElement, SchemeError> {
    let mut group_commitment = GroupElement::identity(group);
    for i in 0..commitment_list.len() {
        let binding_factor;
        if let Ok(factor) =
            binding_factor_for_participant(&binding_factor_list, commitment_list[i].id)
        {
            binding_factor = factor.factor;
        } else {
            return Err(SchemeError::IdNotFound);
        }

        let binding_nonce = commitment_list[i]
            .binding_nonce_commitment
            .pow(&binding_factor);
        group_commitment = group_commitment
            .mul(&commitment_list[i].hiding_nonce_commitment)
            .mul(&binding_nonce);
    }

    Ok(group_commitment)
}

fn compute_challenge(group_commitment: &GroupElement, pk: &FrostPublicKey, msg: &[u8]) -> BigImpl {
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

fn h1(bytes: &[u8], group: &Group) -> BigImpl {
    // TODO: implement for other ciphersuites
    let msg = [get_context_string(group).unwrap(), b"rho", bytes].concat();
    let mut hash = HASH512::new();
    hash.process_array(&msg);
    let h = hash.hash();
    let res = BigImpl::from_bytes(group, &h);
    res.rmod(&group.get_order())
}

fn h2(bytes: &[u8], group: &Group) -> BigImpl {
    // TODO: implement for other ciphersuites
    let mut hash = HASH512::new();
    hash.process_array(&bytes);
    let h = hash.hash();
    let res = BigImpl::from_bytes(group, &h);
    res.rmod(&group.get_order())
}

fn h3(bytes: &[u8], group: &Group) -> BigImpl {
    // TODO: implement for other ciphersuites
    let msg = [get_context_string(group).unwrap(), b"nonce", bytes].concat();
    let mut hash = HASH512::new();
    hash.process_array(&msg);
    let h = hash.hash();
    let res = BigImpl::from_bytes(group, &h);
    res.rmod(&group.get_order())
}

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
