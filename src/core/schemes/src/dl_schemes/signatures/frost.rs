#![allow(non_snake_case)]

use std::{collections::HashMap, hash::Hash};

use asn1::{ParseError, WriteError};

use crate::{
    dl_schemes::common::lagrange_coeff,
    groups::group::GroupElement,
    integers::{bigint::BigInt, sizedint::SizedBigInt},
    interface::{DlShare, SchemeError, Serializable},
    keys::keys::{calc_key_id, PublicKey},
    rand::{RngAlgorithm, RNG},
    scheme_types_impl::GroupDetails,
};
use log::error;
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
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

#[derive(PartialEq, Clone, Debug)]
pub enum FrostOptions {
    PrecomputeOnly,
    Precomputation,
    NoPrecomputation,
}

#[derive(PartialEq, Clone, Debug)]
pub struct FrostThresholdSignature {
    round: u8,
    key: FrostPrivateKey,
    label: Vec<u8>,
    msg: Vec<u8>,
    nonce: Option<Nonce>,
    commitment: Option<PublicCommitment>,
    commitment_list: HashMap<u16, PublicCommitment>,
    precomputation_list: Vec<HashMap<u16, PublicCommitment>>,
    group_commitment: Option<GroupElement>,
    share: Option<FrostSignatureShare>,
    shares: HashMap<u16, FrostSignatureShare>,
    signature: Option<FrostSignature>,
    finished: bool,
    options: FrostOptions,
    signer_group: SignerGroup,
}

impl<'a> FrostThresholdSignature {
    pub fn new(key: &FrostPrivateKey, msg: &[u8], options: FrostOptions) -> Self {
        Self {
            round: 0,
            msg: msg.to_vec(),
            label: Vec::new(),
            shares: HashMap::new(),
            key: key.clone(),
            nonce: Option::None,
            commitment: Option::None,
            precomputation_list: Vec::new(),
            commitment_list: HashMap::new(),
            group_commitment: None,
            share: None,
            finished: false,
            signature: Option::None,
            options,
            signer_group: SignerGroup::new(key.get_threshold()),
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

    // by default we only take the first k shares (ordered by key id), to ensure that every node has the same group of signers
    pub fn update(&mut self, round_result: &FrostRoundResult) -> Result<(), SchemeError> {
        match round_result {
            FrostRoundResult::RoundOne(result) => {
                if let FrostOptions::PrecomputeOnly = self.options {
                    // ignore round one results if only precomputing
                    return Ok(());
                }

                // only accept first commitment for each node (id should be authenticated in the network layer)
                // and id has to be in the signer group
                if self.signer_group.contains(&result.id)
                    && !self.commitment_list.contains_key(&result.id)
                {
                    // todo: need some authentication here to verify id of round result
                    self.commitment_list.insert(result.id, result.clone());
                }

                Ok(())
            }
            FrostRoundResult::RoundTwo(share) => {
                if self.signer_group.contains(&share.id) && !self.shares.contains_key(&share.id) {
                    // todo: authentication
                    let result = self.verify_share(share);
                    if result.is_err() {
                        println!("invalid share with id {}", &share.id);
                        return Err(result.unwrap_err());
                    }

                    self.shares.insert(share.id, share.clone());

                    if self.shares.len() == self.key.get_threshold() as usize {
                        println!("shares len == threshold");
                        // check if we have all required shares to assemble signature
                        if let Option::None = self
                            .signer_group
                            .signer_identifiers
                            .iter()
                            .find(|i| !self.shares.contains_key(&i))
                        {
                            println!("missing shares to reconstruct");
                            return Ok(()); // if not, just return Ok
                        }

                        println!("all required shares aquired, try to assemble signature");
                        // else we try to assemble signature
                        let sig = self.assemble();
                        if sig.is_err() {
                            println!("Error assembling signature");
                            self.finished = true;
                            return Err(sig.unwrap_err());
                        }
                        println!("assembled signature");
                        self.finished = true;
                        self.signature = Some(sig.unwrap());
                    }
                }

                Ok(())
            }
            FrostRoundResult::Precomputation(precomputations) => {
                if precomputations.len() == 0 {
                    return Err(SchemeError::InvalidShare);
                }

                // TODO: use verified id once net layer supports signatures
                println!("precomp id: {}", precomputations[0].id);
                if self.signer_group.contains(&precomputations[0].id) {
                    let mut p: Vec<PublicCommitment>;
                    p = precomputations.clone();

                    // if we should sign and do a precomputation round, pop the first commitment from the stack to use for
                    // the signature in the current execution
                    if self.options == FrostOptions::Precomputation {
                        p = precomputations.clone();
                        let comm = p.pop().unwrap();
                        println!("use first precomp with id {}", comm.get_id());
                        // TODO: use verified id once net layer supports signatures
                        self.commitment_list.insert(comm.get_id() as u16, comm);
                    }

                    if p.len() > 0 {
                        for i in 0..p.len() {
                            if self.precomputation_list.len() < i + 1 {
                                self.precomputation_list.push(HashMap::new());
                            }

                            // TODO: use verified id once net layer supports signatures
                            self.precomputation_list[i].insert(p[i].id, p[i].clone());
                        }
                    }
                }

                Ok(())
            }
        }
    }

    /*
    task: check whether we have all the necessary material to execute the next iteration of self.do_round()
     */
    pub fn is_ready_for_next_round(&self) -> bool {
        match self.round {
            1 => {
                println!("commitment list len: {}", self.commitment_list.len());
                if self.commitment_list.len() >= self.key.get_threshold() as usize {
                    if let Option::Some(_) = self
                        .signer_group
                        .get_vec()
                        .iter()
                        .find(|f| !self.commitment_list.contains_key(&f))
                    {
                        return false;
                    }
                    return true;
                }
                return false;
            }
            2 => {
                if self.shares.len() >= self.key.get_threshold() as usize {
                    if let Option::Some(_) = self
                        .signer_group
                        .get_vec()
                        .iter()
                        .find(|f| !self.shares.contains_key(&f))
                    {
                        return false;
                    }
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
        self.finished
    }

    /*
    task: calculate NUM_PRECOMPUTATIONS commitments and create the according round result
     */
    pub fn precompute(&mut self) -> Result<FrostRoundResult, SchemeError> {
        let mut pc = Vec::new();
        for i in 0..NUM_PRECOMPUTATIONS {
            let res = self.commit(&mut RNG::new(RngAlgorithm::OsRng));

            if res.is_err() {
                return Err(res.unwrap_err());
            }

            if let FrostRoundResult::RoundOne(rr) = res.unwrap() {
                pc.push(rr);
            } else {
                return Err(SchemeError::InvalidRound);
            }
        }

        return Ok(FrostRoundResult::Precomputation(pc));
    }

    /*
    task: return the gathered precomputations (e.g. commitments) from round 1 of the protocol

    returns: a vector of NUM_PRECOMPUTATIONS hash maps containing the commitments if successful
             a SchemeError::WrongState if precomputation is not yet finished or has failed
     */
    pub fn get_precomputations(&self) -> Result<Vec<HashMap<u16, PublicCommitment>>, SchemeError> {
        if self.precomputation_list.len() > 1 && self.finished {
            return Ok(self.precomputation_list.clone());
        }

        Err(SchemeError::WrongState)
    }

    /*
       task: execute one round of the protocol, call the necessary methods of the primitive according to the current round
       returns: FrostRoundResult if execution was successful
                SchemeError::InvalidRound if all roun
    */
    pub fn do_round(&mut self) -> Result<FrostRoundResult, SchemeError> {
        if self.round == 0 {
            let res;
            if (self.options != FrostOptions::NoPrecomputation) {
                res = self.precompute();
            } else {
                res = self.commit(&mut RNG::new(RngAlgorithm::OsRng));
            }

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

    pub(crate) fn partial_sign(&mut self) -> Result<FrostRoundResult, SchemeError> {
        let group = self.key.get_group();
        let order = group.get_order();

        if self.get_nonce().is_none() {
            error!("No nonce set");
            return Err(SchemeError::PreviousRoundNotExecuted);
        }

        let nonce = self.get_nonce().as_ref().unwrap();
        let commitment_list = self.get_commitment_list();

        let binding_factor_list = compute_binding_factors(
            &self.key.pubkey,
            &commitment_list,
            &self.msg,
            &self.key.get_group(),
        );

        let binding_factor = binding_factor_for_participant(&binding_factor_list, self.key.id);
        if binding_factor.is_err() {
            error!("binding factor error");
            return Err(binding_factor.expect_err(""));
        }

        let binding_factor = binding_factor.unwrap();
        let group_commitment = compute_group_commitment(
            &commitment_list,
            &binding_factor_list,
            &self.key.get_group(),
        );
        if group_commitment.is_err() {
            error!("group commitment error");
            return Err(group_commitment.expect_err(""));
        }

        let group_commitment = group_commitment.unwrap();

        let participant_list = participants_from_commitment_list(&commitment_list);
        let lambda_i = lagrange_coeff(&group, &participant_list, self.key.get_share_id() as i32);
        let challenge = compute_challenge(&group_commitment, &self.key.get_public_key(), &self.msg);

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

        self.group_commitment = Option::Some(group_commitment);

        Ok(FrostRoundResult::RoundTwo(FrostSignatureShare {
            id: self.key.get_share_id(),
            data: share,
        }))
    }

    pub(crate) fn commit(&mut self, rng: &mut RNG) -> Result<FrostRoundResult, SchemeError> {
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

    pub(crate) fn assemble(&self) -> Result<FrostSignature, SchemeError> {
        let group_commitment;
        if let Some(group_commit) = &self.group_commitment {
            group_commitment = group_commit;
        } else {
            return Err(SchemeError::WrongState);
        }

        let mut z = SizedBigInt::new_int(&group_commitment.get_group(), 0);
        for i in 0..self.key.get_threshold() {
            z = z
                .add(&self.shares[&(i as u16)].data)
                .rmod(&self.shares[&(i as u16)].data.get_group().get_order());
        }

        Ok(FrostSignature {
            R: group_commitment.clone(),
            z,
        })
    }

    pub(crate) fn verify_share(&self, share: &FrostSignatureShare) -> Result<bool, SchemeError> {
        let commitment_list = self.get_commitment_list();
        let pk = &self.key.pubkey;
        if self.get_commitment().is_none() {
            return Err(SchemeError::PreviousRoundNotExecuted);
        }

        let commitment = self.commitment_list.get(&(share.get_id() as u16));
        if commitment.is_none() {
            return Err(SchemeError::IdNotFound);
        }
        let commitment = commitment.unwrap();

        let binding_factor_list = compute_binding_factors(
            &self.key.pubkey,
            &commitment_list,
            &self.msg,
            &self.key.get_group(),
        );
        let binding_factor = binding_factor_for_participant(&binding_factor_list, share.get_id());
        if binding_factor.is_err() {
            return Err(binding_factor.expect_err(""));
        }

        let binding_factor = binding_factor.unwrap();
        let group_commitment =
            compute_group_commitment(&commitment_list, &binding_factor_list, &pk.get_group());
        if group_commitment.is_err() {
            return Err(group_commitment.expect_err(""));
        }

        let group_commitment = group_commitment.unwrap();

        let comm_share = commitment.hiding_nonce_commitment.mul(
            &commitment
                .binding_nonce_commitment
                .pow(&binding_factor.factor),
        );

        let challenge = compute_challenge(&group_commitment, pk, &self.msg);
        let participant_list = participants_from_commitment_list(&commitment_list);
        let lambda_i = lagrange_coeff(&pk.get_group(), &participant_list, share.get_id() as i32);

        let l = GroupElement::new_pow_big(&pk.get_group(), &share.data);
        let r = comm_share.mul(
            &pk.get_verification_key(share.get_id())
                .pow(&lambda_i.mul_mod(&challenge, &pk.get_group().get_order())),
        );

        Ok(l.eq(&r))
    }

    pub(crate) fn get_nonce(&self) -> &Option<Nonce> {
        &self.nonce
    }

    pub(crate) fn get_commitment(&self) -> &Option<PublicCommitment> {
        &self.commitment
    }

    pub(crate) fn get_commitment_list(&self) -> Vec<PublicCommitment> {
        self.commitment_list.clone().into_values().collect()
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
    Precomputation(Vec<PublicCommitment>),
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
}

pub fn get_share(instance: &FrostThresholdSignature) -> Result<FrostSignatureShare, SchemeError> {
    if instance.share.is_none() {
        return Err(SchemeError::WrongState);
    }

    Ok(instance.share.clone().unwrap())
}

pub(crate) fn nonce_generate(secret: &SizedBigInt, rng: &mut RNG) -> SizedBigInt {
    let random_bytes = rng.random_bytes(32);
    let secret_bytes = serialize_scalar(secret);
    return h3(&[random_bytes, secret_bytes].concat(), &secret.get_group());
}

pub(crate) fn compute_binding_factors(
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

pub(crate) fn compute_group_commitment(
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

    let modulo = BigInt::from_bytes(
        &hex::decode("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED").unwrap(),
    );
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
    bytes[0] &= 0x1f;
    bytes
}

#[derive(Debug, PartialEq, Clone)]
struct SignerGroup {
    signer_identifiers: Vec<u16>,
}

impl SignerGroup {
    /* creates a new signer group with ids from 1 to n */
    pub fn new(n: u16) -> Self {
        let signer_identifiers: Vec<u16> = (1..n + 1).collect();
        Self { signer_identifiers }
    }

    /* creates a new signer group from a vector of ids */
    pub fn from_vec(ids: &Vec<u16>) -> Self {
        Self {
            signer_identifiers: ids.clone(),
        }
    }

    /* include id in group */
    pub fn include(&mut self, id: &u16) {
        self.signer_identifiers.push(id.clone());
    }

    /* exclude id from group */
    pub fn exclude(&mut self, id: &u16) {
        self.signer_identifiers.retain(|v| !v.eq(id));
    }

    /* check if id is part of group */
    pub fn contains(&self, id: &u16) -> bool {
        self.signer_identifiers.contains(id)
    }

    /* return vector of signer identifiers */
    pub fn get_vec(&self) -> &Vec<u16> {
        &self.signer_identifiers
    }
}
