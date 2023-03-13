use std::convert::TryInto;

use asn1::{WriteError, ParseError};
use chacha20poly1305::aead::generic_array::typenum::Gr;

use mcore::hash512::HASH512;
use crate::{dl_schemes::{bigint::{BigImpl, BigInt}, common::{shamir_share, lagrange_coeff}}, group::{GroupElement, Group}, interface::{ThresholdCryptoError, Serializable}, rand::{RNG, RngAlgorithm}, rsa_schemes::bigint::RsaBigInt};

const CONTEXT_STRING:&[u8] = b"FROST-ED25519-SHA512-v8";

#[derive(Clone, Debug, PartialEq)]
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

impl Serializable for FrostPublicKey {
    fn serialize(&self) -> Result<Vec<u8>, ThresholdCryptoError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&self.get_group().get_code())?;
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
            return Err(ThresholdCryptoError::SerializationFailed);
        }

        Ok(result.unwrap())
    }

    fn deserialize(bytes: &Vec<u8>) -> Result<Self, ThresholdCryptoError>  {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let n = d.read_element::<u64>()? as u16;
                let k = d.read_element::<u64>()? as u16;
                let group = Group::from_code(d.read_element::<u8>()?);
                
                let bytes = d.read_element::<&[u8]>()?;
                let y = GroupElement::from_bytes(&bytes, &group, Option::None);
                
                let mut h = Vec::new();

                for _i in 0..n {
                    let bytes = d.read_element::<&[u8]>()?;
                    h.push(GroupElement::from_bytes(&bytes, &group, Option::None));
                }

                let bytes = d.read_element::<&[u8]>()?;
                let g_bar = GroupElement::from_bytes(&bytes, &group, Option::None);

                Ok(Self{n, k, group, y, h})
            })
        });

        if result.is_err() {
            println!("{}", result.err().unwrap().to_string());
            return Err(ThresholdCryptoError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}


#[derive(Debug, Clone, PartialEq)]
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

impl Serializable for FrostPrivateKey {
    fn serialize(&self) -> Result<Vec<u8>, ThresholdCryptoError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                w.write_element(&self.x.to_bytes().as_slice())?;

                let bytes = self.pubkey.serialize();
                if bytes.is_err() {
                    return Err(WriteError::AllocationError);
                }

                w.write_element(&bytes.unwrap().as_slice())?;
                Ok(())
            }))
        });

        if result.is_err() {
            return Err(ThresholdCryptoError::SerializationFailed);
        }

        Ok(result.unwrap())
    }

    fn deserialize(bytes: &Vec<u8>) -> Result<Self, ThresholdCryptoError>  {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let id = d.read_element::<u64>()? as u16;
                let bytes = d.read_element::<&[u8]>()?;
                let pubbytes = d.read_element::<&[u8]>()?;
                let res = FrostPublicKey::deserialize(&pubbytes.to_vec());
                if res.is_err() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault { }));
                }

                let pubkey = res.unwrap();

                let x = BigImpl::from_bytes(&pubkey.get_group(), &bytes);

                return Ok(Self {id, x, pubkey});
            })
        });

        if result.is_err() {
            println!("{}", result.err().unwrap().to_string());
            return Err(ThresholdCryptoError::DeserializationFailed);
        }

        Ok(result.unwrap())
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

#[derive(PartialEq, Clone)]
pub struct Nonce {
    hiding_nonce: BigImpl,
    binding_nonce: BigImpl
}

#[derive(Debug, Clone)]
pub struct BindingFactor {
    id: u16,
    factor: BigImpl
}

#[derive(Debug, PartialEq, Clone)]
pub struct FrostSignatureShare {
    id: u16,
    data: BigImpl
}

impl FrostSignatureShare {
    pub fn get_id(&self) -> u16 {
        self.id
    }
}

impl Serializable for FrostSignatureShare {
    fn serialize(&self) -> Result<Vec<u8>, ThresholdCryptoError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                w.write_element(&self.data.get_group().get_code())?;
                w.write_element(&self.data.to_bytes().as_slice())?;
                Ok(())
            }))
        });

        if result.is_err() {
            return Err(ThresholdCryptoError::SerializationFailed);
        }

        Ok(result.unwrap())
    }

    fn deserialize(bytes: &Vec<u8>) -> Result<Self, ThresholdCryptoError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let id = d.read_element::<u64>()? as u16;
                let group = Group::from_code(d.read_element::<u8>()?);
                let data = BigImpl::from_bytes(&group, &bytes);
                
                return Ok(Self { id, data});
            })
        });

        if result.is_err() {
            println!("{}", result.err().unwrap().to_string());
            return Err(ThresholdCryptoError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}


#[derive(Debug, PartialEq, Clone)]
pub struct FrostSignature { /* TODO: encode according to standard */
    R: GroupElement,
    z: BigImpl
}

impl Serializable for FrostSignature {
    fn serialize(&self) -> Result<Vec<u8>, ThresholdCryptoError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&self.R.get_group().get_code())?;
                w.write_element(&self.R.to_bytes().as_slice())?;
                w.write_element(&self.z.to_bytes().as_slice())?;
                Ok(())
            }))
        });

        if result.is_err() {
            return Err(ThresholdCryptoError::SerializationFailed);
        }

        Ok(result.unwrap())
    }

    fn deserialize(bytes: &Vec<u8>) -> Result<Self, ThresholdCryptoError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let group = Group::from_code(d.read_element::<u8>()?);
                let label = d.read_element::<&[u8]>()?.to_vec();
                
                let bytes = d.read_element::<&[u8]>()?;
                let R = GroupElement::from_bytes(&bytes, &group, Option::None);

                let bytes = d.read_element::<&[u8]>()?;
                let z = BigImpl::from_bytes(&group, &bytes);

                return Ok(Self { R, z });
            })
        });

        if result.is_err() {
            println!("{}", result.err().unwrap().to_string());
            return Err(ThresholdCryptoError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}


#[derive(PartialEq, Clone)]
pub struct FrostThresholdSignature<'a> {
    round: u8,
    key: &'a FrostPrivateKey,
    msg: Option<Vec<u8>>,
    nonce: Option<Nonce>,
    commitment: Option<PublicCommitment>,
    commitment_list: Vec<PublicCommitment>,
    group_commitment: Option<GroupElement>,
    share: Option<FrostSignatureShare>,
    shares: Vec<FrostSignatureShare>,
    signature: Option<FrostSignature>,
    finished: bool
}

impl<'a> FrostThresholdSignature<'a> {
    pub fn new(key: &'a FrostPrivateKey) -> Self {
        Self {round:0, msg:None, shares:Vec::new(), key, nonce:Option::None, commitment:Option::None, commitment_list: Vec::new(), group_commitment:None, share:None, finished: false, signature:Option::None}
    }

    pub fn set_msg(&mut self, msg: &'a[u8]) -> Result<(), ThresholdCryptoError> {
        if self.msg.is_some() {
            return Err(ThresholdCryptoError::MessageAlreadySpecified);
        }
        self.msg = Some(msg.to_vec());
        Ok(())
    }

    pub fn update(&mut self, round_result: &FrostRoundResult) -> Result<(), ThresholdCryptoError> {
        match round_result {
            FrostRoundResult::RoundOne(result) => {
                self.commitment_list.push(result.clone());
                Ok(())
            },
            FrostRoundResult::RoundTwo(share) => {
                let result = self.verify_share(share);
                if result.is_err() {
                    return Err(result.unwrap_err());
                }

                if !result.unwrap() {
                    println!("invalid share");
                    return Err(ThresholdCryptoError::InvalidShare);
                }

                self.shares.push(share.clone());

                println!("share added");

                if self.shares.len() == self.key.get_threshold() as usize {
                    println!("all shares received");
                    let sig = self.assemble();
                    if sig.is_err() {
                        return Err(sig.unwrap_err());
                    }

                    self.signature = Some(sig.unwrap());
                }

                Ok(())
            },
            _ => Err(ThresholdCryptoError::InvalidRound)
        }
    }

    pub fn is_ready_for_next_round(&self) -> bool {
        match self.round {
            1 => {
                if self.commitment_list.len() >= self.key.get_threshold() as usize {
                    return true;
                }
                return false;
            },
            2 => {
                if self.shares.len() >= self.key.get_threshold() as usize {
                    return true;
                }
                return false;
            },
            _ => return false
        }
    }

    pub fn get_signature(&self) -> Result<FrostSignature, ThresholdCryptoError> {
        if self.signature.is_none() {
            return Err(ThresholdCryptoError::ProtocolNotFinished);
        }

        Ok(self.signature.clone().unwrap())
    }

    pub fn is_finished(&self) -> bool {
        self.round == 2 && self.signature.is_some()
    }

    pub fn do_round(&mut self) -> Result<FrostRoundResult, ThresholdCryptoError> {
        if self.round == 0 {
            let res = self.commit(&mut RNG::new(RngAlgorithm::MarsagliaZaman));
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

        Err(ThresholdCryptoError::InvalidRound)
    }

    fn partial_sign(&mut self) -> Result<FrostRoundResult, ThresholdCryptoError> {
        let group = self.key.get_group();
        let order = group.get_order();
        let msg = self.msg.as_ref().unwrap();

        if self.get_nonce().is_none() {
            return Err(ThresholdCryptoError::PreviousRoundNotExecuted);
        }

        if self.msg.is_none() {
            return Err(ThresholdCryptoError::MessageNotSpecified);
        }

        let nonce = self.get_nonce().as_ref().unwrap();
        let commitment_list = self.get_commitment_list();
        
        let binding_factor_list = compute_binding_factors(commitment_list, msg, &self.key.get_group());

        let binding_factor = binding_factor_for_participant(&binding_factor_list, self.key.id);
        if binding_factor.is_err() {
            return Err(binding_factor.expect_err(""));
        }

        let binding_factor = binding_factor.unwrap();
        let group_commitment = compute_group_commitment(commitment_list, &binding_factor_list, &self.key.get_group());
        if group_commitment.is_err() {
            return Err(group_commitment.expect_err(""));
        }

        let group_commitment = group_commitment.unwrap();     

        let participant_list = participants_from_commitment_list(commitment_list);
        let lambda_i = lagrange_coeff(&group, &participant_list, self.key.get_id() as i32);
        let challenge = compute_challenge(&group_commitment, &self.key.get_public_key(), msg);

        print!("sign part. list({}): ", self.key.get_id());

        for i in 0..participant_list.len() {
            print!("{}", participant_list[i]);
        }
        print!("\n");

        println!("sign lambda: {} chall: {} binding_factor: {}", lambda_i.to_string(), challenge.to_string(), binding_factor.factor.to_string());

        let share = 
            nonce.hiding_nonce
            .add(
                &nonce.binding_nonce
                .mul_mod(&binding_factor.factor, &order)
                )
            .rmod(&order)
            .add(
                 &lambda_i
                 .mul_mod(&self.key.x, &order)
                 .mul_mod(&challenge, &order)
                )
            .rmod(&order);

        //self.commitment_list = commitment_list.to_vec();
        self.group_commitment = Option::Some(group_commitment);

        Ok(FrostRoundResult::RoundTwo(FrostSignatureShare { id: self.key.get_id(), data:share }))
    }

    fn commit(&mut self, rng: &mut RNG) -> Result<FrostRoundResult, ThresholdCryptoError> {
        let hiding_nonce = nonce_generate(&self.key.x, rng);
        let binding_nonce = nonce_generate(&self.key.x, rng);
        let hiding_nonce_commitment = GroupElement::new_pow_big(&self.key.get_group(), &hiding_nonce);
        let binding_nonce_commitment = GroupElement::new_pow_big(&self.key.get_group(), &binding_nonce);
        let nonce = Nonce { hiding_nonce, binding_nonce };
        let comm = PublicCommitment { id: self.key.get_id(), hiding_nonce_commitment, binding_nonce_commitment };

       //FrostThresholdSignature { nonce, commitment:comm, commitment_list:Vec::new(), group_commitment:Option::None, share:Option::None }
        self.commitment = Some(comm.clone());
        self.nonce = Some(nonce.clone());

        Ok(FrostRoundResult::RoundOne(comm))
    }

    fn assemble(&self) -> Result<FrostSignature, ThresholdCryptoError> {
        let group_commitment;
        if let Some(group_commit) = &self.group_commitment {
            group_commitment = group_commit;
        } else {
            return Err(ThresholdCryptoError::WrongState);
        }

        let mut z = BigImpl::new_int(&group_commitment.get_group(), 0);
        for i in 0..self.shares.len() {
            z = z.add(&self.shares[i].data).rmod(&self.shares[i].data.get_group().get_order());
        }

        Ok(FrostSignature { R: group_commitment.clone(), z })
    }

    fn verify_share(&self, share: &FrostSignatureShare) -> Result<bool, ThresholdCryptoError> {
        let commitment_list = self.get_commitment_list();
        let pk = &self.key.pubkey;
        let msg = self.msg.as_ref().unwrap();
        if self.get_commitment().is_none() {
            return Err(ThresholdCryptoError::PreviousRoundNotExecuted);
        }

        if self.msg.is_none() {
            return Err(ThresholdCryptoError::MessageNotSpecified);
        }

        let commitment = commitment_for_participant(&self.commitment_list, share.get_id());
        if commitment.is_err() {
            return Err(commitment.expect_err(""));
        }
        let commitment = commitment.unwrap();

        let binding_factor_list = compute_binding_factors(&commitment_list, msg, &self.key.get_group());
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

    fn get_nonce(&self) -> &Option<Nonce> {
        &self.nonce
    }

    fn get_commitment(&self) -> &Option<PublicCommitment> {
        &self.commitment
    }

    fn get_commitment_list(&self) -> &Vec<PublicCommitment> {
        &self.commitment_list
    }

    fn get_group_commitment(&self) -> &Option<GroupElement> {
        &self.group_commitment
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
    RoundTwo(FrostSignatureShare)
}

    

pub fn get_share(instance: &FrostThresholdSignature) -> Result<FrostSignatureShare, ThresholdCryptoError> {
    if instance.share.is_none() {
        return Err(ThresholdCryptoError::WrongState);
    }

    Ok(instance.share.clone().unwrap())
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

fn commitment_for_participant(commitment_list: &[PublicCommitment], identifier: u16) -> Result<PublicCommitment, ThresholdCryptoError> {
    for i in 0..commitment_list.len() {
        if identifier as u16 == commitment_list[i].id {
            return Ok(commitment_list[i].clone());
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
