use std::convert::TryInto;

use crate::{dl_schemes::{bigint::{BigImpl, BigInt}, common::{shamir_share, lagrange_coeff}}, group::GroupElement, interface::ThresholdCryptoError, rand::{RNG, RngAlgorithm}, proto::scheme_types::{Group, ThresholdScheme}, rsa_schemes::bigint::RsaBigInt};
use chacha20poly1305::aead::generic_array::typenum::Gr;
use derive::Serializable;
use mcore::hash512::HASH512;
use rasn::{AsnType, Decode, Encode};

const CONTEXT_STRING:&[u8] = b"FROST-ED25519-SHA512-v8";

#[derive(Clone, Debug, PartialEq, AsnType, Serializable)]
pub struct FrostPublicKey {
    n: u16,
    k: u16,
    group: Group,
    y: GroupElement,
    h: Vec<GroupElement>
}

impl FrostPublicKey {
    pub fn new(n: usize, k:usize, group: &Group, y: &GroupElement, h: &Vec<GroupElement>) -> Self {
        Self {
           n:n as u16,
           k:k as u16,
           group:group.clone(),
           y: y.clone(),
           h: h.clone() 
        }
    }

    pub fn get_group(&self) -> Group {
        self.group.clone()
    }

    pub fn get_verification_key(&self, id: u16) -> GroupElement {
        self.h[(id - 1) as usize].clone()
    }

    pub fn get_n(&self) -> u16 {
        self.n
    }

    pub fn get_threshold(&self) -> u16 {
        self.k
    }
}


impl Encode for FrostPublicKey {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.get_group().get_code().encode(sequence)?;
            self.n.encode(sequence)?;
            self.k.encode(sequence)?;
            self.y.to_bytes().encode(sequence)?;
            for i in 0..self.h.len() {
                self.h[i].to_bytes().encode(sequence)?;
            }
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for FrostPublicKey {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let group = Group::from_code(u8::decode(sequence)?);
            let n = u16::decode(sequence)?;
            let k = u16::decode(sequence)?;
            let y_b = Vec::<u8>::decode(sequence)?;
            let mut h = Vec::new();

            for _i in 0..n {
                let bytes = Vec::<u8>::decode(sequence)?;
                h.push(GroupElement::from_bytes(&bytes, &group, Option::None));
            }

            let y = GroupElement::from_bytes(&y_b, &group, Option::Some(0));

            Ok(Self{group, n, k, y, h})
        })
    }
}


#[derive(Debug, Clone, PartialEq, AsnType, Serializable)]
pub struct FrostPrivateKey {
    id: u16,
    x: BigImpl,
    pubkey: FrostPublicKey
}

impl FrostPrivateKey {
    pub fn new(id:usize, x: &BigImpl, pubkey: &FrostPublicKey) -> Self {
        Self {
            id:id as u16,
            x:x.clone(),
            pubkey:pubkey.clone()
        }
    }

    pub fn get_id(&self) -> u16 {
        self.id
    }

    pub fn get_group(&self) -> Group {
        self.pubkey.get_group()
    }

    pub fn get_threshold(&self) -> u16 {
        self.pubkey.get_threshold()
    }
    
    pub fn get_public_key(&self) -> FrostPublicKey {
        self.pubkey.clone()
    }
}

impl Encode for FrostPrivateKey {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.id.encode(sequence)?;
            self.x.to_bytes().encode(sequence)?;
            self.pubkey.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for FrostPrivateKey {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let id = u16::decode(sequence)?;
            let x_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let pubkey = FrostPublicKey::decode(sequence)?;
            let x = BigImpl::from_bytes(&pubkey.group, &x_bytes);

            Ok(Self {id, x, pubkey})
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PublicCommitment {
    id: u16,
    hiding_nonce_commitment: GroupElement,
    binding_nonce_commitment: GroupElement
}

impl PublicCommitment {
    pub fn get_id(&self) -> u16 {
        self.id
    }
}

/*
struct FrostCommitmentShare {
    d: GroupElement,
    e: GroupElement
}

impl FrostCommitmentShare {
    fn new(group: &Group, rng: &mut RNG) -> Self {
        let _d = BigImpl::new_rand(group, &group.get_order(), rng);
        let _e = BigImpl::new_rand(group, &group.get_order(), rng);
        Self { d: GroupElement::new_pow_big(group, &_d), e: GroupElement::new_pow_big(group, &_e) }
    }
}*/


#[derive(AsnType, PartialEq, Clone)]
pub struct Nonce {
    hiding_nonce: BigImpl,
    binding_nonce: BigImpl
}

#[derive(Debug, Clone)]
pub struct BindingFactor {
    id: u16,
    factor: BigImpl
}

#[derive(AsnType, PartialEq, Clone, Serializable)]
pub struct FrostSignatureShare {
    id: u16,
    data: BigImpl
}

impl FrostSignatureShare {
    pub fn get_id(&self) -> u16 {
        self.id
    }
}

impl Encode for FrostSignatureShare {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.id.encode(sequence)?;
            self.data.get_group().get_code().encode(sequence)?;
            self.data.to_bytes().encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for FrostSignatureShare {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let id = u16::decode(sequence)?;
            let group = Group::from_code(u8::decode(sequence)?);
            let data_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let data = BigImpl::from_bytes(&group, &data_bytes);

            Ok(Self {id, data})
        })
    }
}

#[derive(AsnType, PartialEq, Clone, Serializable)]
pub struct FrostSignature { /* TODO: encode according to standard */
    R: GroupElement,
    z: BigImpl
}

impl Encode for FrostSignature {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.R.get_group().get_code().encode(sequence)?;
            self.R.to_bytes().encode(sequence)?;
            self.z.to_bytes().encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for FrostSignature {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let group = Group::from_code(u8::decode(sequence)?);
            let R_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let z_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let R = GroupElement::from_bytes(&z_bytes, &group, None);
            let z = BigImpl::from_bytes(&group, &z_bytes);

            Ok(Self {R, z})
        })
    }
}

#[derive(AsnType, PartialEq, Clone)]
pub struct FrostInstance {
    nonce: Vec<Nonce>,
    commitment: Vec<PublicCommitment>,
    commitment_list: Vec<PublicCommitment>,
    group_commitment: Option<GroupElement>,
    share: Option<FrostSignatureShare>,
    round_results: Vec<FrostRoundResult>
}

impl FrostInstance {
    pub fn new() -> Self {
        Self {nonce:Vec::new(), commitment:Vec::new(), commitment_list: Vec::new(), group_commitment:None, share:None, round_results: Vec::new()}
    }

    pub fn get_nonce(&self) -> &Nonce {
        &self.nonce[0]
    }

    pub fn get_commitment(&self) -> &PublicCommitment {
        &self.commitment[0]
    }

    pub fn get_commitment_list(&self) -> &Vec<PublicCommitment> {
        &self.commitment_list
    }

    pub fn get_group_commitment(&self) -> &Option<GroupElement> {
        &self.group_commitment
    }

    pub fn set_commitments(&mut self, commitment_list: &[PublicCommitment]) {
        self.commitment_list = commitment_list.to_vec();
    }

    pub fn process_round_results(&mut self, round_results: &Vec<FrostRoundResult>) {
        for i in 0..round_results.len() {
            self.commitment_list.push(round_results[i].public_commitment.clone().unwrap());
        }
    }
}

#[derive(AsnType, PartialEq, Clone)]
pub struct FrostRoundResult {
    id: u16,
    public_commitment: Option<PublicCommitment>,
    share: Option<FrostSignatureShare>
}

impl FrostRoundResult {
    pub fn get_share(&self) -> FrostSignatureShare {
        self.share.clone().unwrap()
    }
}

#[derive(AsnType, PartialEq, Clone)]
pub struct FrostThresholdSignature {
    group_commitment: GroupElement
}

impl FrostThresholdSignature {
    pub fn generate_keys(k: usize, n: usize, rng: &mut RNG, group: &Group) -> Result<Vec<FrostPrivateKey>, ThresholdCryptoError> {
        let x = BigImpl::new_rand(group, &group.get_order(), rng);
        let y = GroupElement::new_pow_big(&group, &x);
    
        let (shares, h): (Vec<BigImpl>, Vec<GroupElement>) = shamir_share(&x, k as usize, n as usize, rng);
        let mut private_keys = Vec::new();
    
        let public_key = FrostPublicKey::new(n, k, group, &y, &h );
    
        for i in 0..shares.len() {
            private_keys.push(FrostPrivateKey::new((i+1).try_into().unwrap(), &shares[i], &public_key));
        }
    
        return Result::Ok(private_keys);
    }

    pub fn partial_sign(sk: &FrostPrivateKey, msg: &[u8], instance: &mut FrostInstance) -> Result<FrostRoundResult, ThresholdCryptoError> {
        let group = sk.get_group();
        let order = group.get_order();
        let nonce = instance.get_nonce();
        let commitment_list = instance.get_commitment_list();

        let binding_factor_list = compute_binding_factors(commitment_list, msg, &sk.get_group());
        let binding_factor = binding_factor_for_participant(&binding_factor_list, sk.id);
        if binding_factor.is_err() {
            return Err(binding_factor.expect_err(""));
        }

        let binding_factor = binding_factor.unwrap();
        let group_commitment = compute_group_commitment(commitment_list, &binding_factor_list, &sk.get_group());
        if group_commitment.is_err() {
            return Err(group_commitment.expect_err(""));
        }

        let group_commitment = group_commitment.unwrap();

        let participant_list = participants_from_commitment_list(commitment_list);
        let lambda_i = lagrange_coeff(&group, &participant_list, sk.get_id() as i32);
        let challenge = compute_challenge(&group_commitment, &sk.get_public_key(), msg);

        let share = 
            nonce.hiding_nonce
            .add(
                &nonce.binding_nonce
                .mul_mod(&binding_factor.factor, &order)
                )
            .rmod(&order)
            .add(
                 &lambda_i
                 .mul_mod(&sk.x, &order)
                 .mul_mod(&challenge, &order)
                )
            .rmod(&order);

        instance.commitment_list = commitment_list.to_vec();
        instance.group_commitment = Option::Some(group_commitment);

        Ok(FrostRoundResult {share: Some(FrostSignatureShare { id: sk.get_id(), data:share }), id: sk.id, public_commitment:None})
    }

    pub fn verify_share(share: &FrostSignatureShare, pk: &FrostPublicKey, instance: &FrostInstance, msg: &[u8]) -> Result<bool, ThresholdCryptoError> {
        let commitment_list = instance.get_commitment_list();
        
        let commitment = instance.get_commitment();

        let binding_factor_list = compute_binding_factors(&commitment_list, &msg, &pk.get_group());
        let binding_factor = binding_factor_for_participant(&binding_factor_list, share.get_id());
        if binding_factor.is_err() {
            return Err(binding_factor.expect_err(""));
        }

        let binding_factor = binding_factor.unwrap();
        let group_commitment = compute_group_commitment(commitment_list, &binding_factor_list, &pk.get_group());
        if group_commitment.is_err() {
            return Err(group_commitment.expect_err(""));
        }

        let group_commitment = group_commitment.unwrap();

        let comm_share = commitment.hiding_nonce_commitment.mul(&commitment.binding_nonce_commitment.pow(&binding_factor.factor));

        let challenge = compute_challenge(&group_commitment, pk, msg);
        let participant_list = participants_from_commitment_list(commitment_list);
        let lambda_i = lagrange_coeff(&pk.get_group(), &participant_list, share.get_id() as i32);

        let l = GroupElement::new_pow_big(&pk.get_group(), &share.data);
        let r = comm_share.mul(&pk.get_verification_key(share.get_id()).pow(&lambda_i.mul_mod(&challenge, &pk.get_group().get_order())));

        Ok(l.eq(&r))
    }

    pub fn commit(sk: &FrostPrivateKey, rng: &mut RNG, instance: &mut FrostInstance) -> Result<FrostRoundResult, ThresholdCryptoError> {
        let hiding_nonce = nonce_generate(&sk.x, rng);
        let binding_nonce = nonce_generate(&sk.x, rng);
        let hiding_nonce_commitment = GroupElement::new_pow_big(&sk.get_group(), &hiding_nonce);
        let binding_nonce_commitment = GroupElement::new_pow_big(&sk.get_group(), &binding_nonce);
        let nonce = Nonce { hiding_nonce, binding_nonce };
        let comm = PublicCommitment { id: sk.get_id(), hiding_nonce_commitment, binding_nonce_commitment };

       //FrostInstance { nonce, commitment:comm, commitment_list:Vec::new(), group_commitment:Option::None, share:Option::None }
        instance.commitment.push(comm.clone());
        instance.nonce.push(nonce);

        Ok(FrostRoundResult { id: sk.id, public_commitment: Some(comm), share:None })
    }

    pub fn assemble(instance: &FrostInstance, sig_shares: &Vec<FrostSignatureShare>) -> Result<FrostSignature, ThresholdCryptoError> {
        let group_commitment;
        if let Some(group_commit) = instance.get_group_commitment() {
            group_commitment = group_commit;
        } else {
            return Err(ThresholdCryptoError::WrongState);
        }

        let mut z = BigImpl::new_int(&group_commitment.get_group(), 0);
        for i in 0..sig_shares.len() {
            z = z.add(&sig_shares[i].data).rmod(&sig_shares[i].data.get_group().get_order());
        }

        Ok(FrostSignature { R: group_commitment.clone(), z })
    }

    pub fn verify(signature: &FrostSignature, pk: &FrostPublicKey, msg: &[u8]) -> bool {
        let challenge = compute_challenge(&signature.R, pk, msg);
        
        let l = GroupElement::new_pow_big(&pk.get_group(), &signature.z);
        let r = signature.R.mul(&pk.y.pow(&challenge));
        l.eq(&r)
    }

    pub fn get_share(instance: &FrostInstance) -> Result<FrostSignatureShare, ThresholdCryptoError> {
        if instance.share.is_none() {
            return Err(ThresholdCryptoError::WrongState);
        }

        Ok(instance.share.clone().unwrap())
    }

    pub fn sign_round(sk: &FrostPrivateKey, msg: &[u8], instance: &mut FrostInstance, round: u8) -> Result<FrostRoundResult, ThresholdCryptoError> {
        if round > ThresholdScheme::Frost.get_rounds() {
            return Err(ThresholdCryptoError::InvalidRound);
        }

        match round {
            0 => return Self::commit(&sk, &mut RNG::new(RngAlgorithm::MarsagliaZaman), instance),
            1 => return Self::partial_sign(&sk, msg, instance),
            _ => return Err(ThresholdCryptoError::InvalidRound)
        }
    }
}

fn nonce_generate(secret: &BigImpl, rng: &mut RNG) -> BigImpl {
    let k_enc = rng.random_bytes(32);
    let secret_enc = secret.to_bytes();
    return h3(&[k_enc, secret_enc].concat(), &secret.get_group());
}

fn compute_binding_factors(commitment_list: &[PublicCommitment], msg: &[u8], group: &Group) -> Vec<BindingFactor> {
    let msg_hash = h4(msg, group);
    let encoded_commitment_hash = h5(&encode_group_commitment_list(commitment_list), group);
    let rho_input_prefix = [msg_hash, encoded_commitment_hash].concat();

    let mut binding_factor_list:Vec<BindingFactor> = Vec::new();
    for i in 0..commitment_list.len() {
        let rho_input = [rho_input_prefix.clone(), encode_uint16(commitment_list[i].id)].concat();
        let binding_factor = h1(&rho_input, group);
        binding_factor_list.push(BindingFactor {id:commitment_list[i].id, factor:binding_factor});
    }

    return binding_factor_list;
}

fn compute_group_commitment(commitment_list: &[PublicCommitment], binding_factor_list: &Vec<BindingFactor>, group: &Group) -> Result<GroupElement, ThresholdCryptoError> {
    let mut group_commitment = GroupElement::identity(group);
    for i in 0..commitment_list.len() {
        let binding_factor;
        if let Ok(factor) = binding_factor_for_participant(&binding_factor_list, commitment_list[i].id) {
            binding_factor = factor.factor;
        } else {
            return Err(ThresholdCryptoError::IdNotFound);
        }

        group_commitment = group_commitment.mul(&commitment_list[i].hiding_nonce_commitment).mul(&commitment_list[i].binding_nonce_commitment.pow(&binding_factor));
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
        let enc_comm = 
            [encode_uint16(commitment_list[i].id), 
            commitment_list[i].hiding_nonce_commitment.to_bytes(),
            commitment_list[i].binding_nonce_commitment.to_bytes()]
            .concat();
        encoded = [encoded, enc_comm].concat();
    }

    encoded
}

fn binding_factor_for_participant(binding_factor_list: &Vec<BindingFactor> , identifier: u16) -> Result<BindingFactor, ThresholdCryptoError> {
    for i in 0..binding_factor_list.len() {
        if identifier as u16 == binding_factor_list[i].id {
            return Ok(binding_factor_list[i].clone());
        }
    }

    Err(ThresholdCryptoError::IdNotFound)
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

fn h1(bytes: &[u8], group: &Group) -> BigImpl { // TODO: implement for other ciphersuites
    let msg = [CONTEXT_STRING, b"rho", bytes].concat(); 
    let mut hash = HASH512::new();
    hash.process_array(&msg);
    let h = hash.hash();
    let mut res = BigImpl::from_bytes(group, &h);
    res.rmod(&group.get_order());
    res
}

fn h2(bytes: &[u8], group: &Group) -> BigImpl { // TODO: implement for other ciphersuites 
    let mut hash = HASH512::new();
    hash.process_array(&bytes);
    let h = hash.hash();
    let mut res = BigImpl::from_bytes(group, &h);
    res.rmod(&group.get_order());
    res
}

fn h3(bytes: &[u8], group: &Group) -> BigImpl { // TODO: implement for other ciphersuites
    let msg = [CONTEXT_STRING, b"nonce", bytes].concat(); 
    let mut hash = HASH512::new();
    hash.process_array(&msg);
    let h = hash.hash();
    let mut res = BigImpl::from_bytes(group, &h);
    res.rmod(&group.get_order());
    res
}

fn h4(bytes: &[u8], group: &Group) -> [u8;64] { // TODO: implement for other ciphersuites
    let msg = [CONTEXT_STRING, b"msg", bytes].concat(); 
    let mut hash = HASH512::new();
    hash.process_array(&msg);
    hash.hash()
}

fn h5(bytes: &[u8], group: &Group) -> [u8;64] { // TODO: implement for other ciphersuites
    let msg = [CONTEXT_STRING, b"com", bytes].concat(); 
    let mut hash = HASH512::new();
    hash.process_array(&msg);
    hash.hash()
}
