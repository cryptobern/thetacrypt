#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; 
use chacha20poly1305::aead::{Aead, NewAead};
use derive::{PublicKey, PrivateKey, DlShare, Ciphertext, Serializable};
use mcore::bls12381::big;
use mcore::hash256::*;
use rasn::{AsnType, Tag, Encode, Decode};

use crate::dl_schemes::bigint::*;
use crate::dl_schemes::{common::*};
use crate::group::{Group, GroupElement};
use crate::interface::{ThresholdCipherParams, ThresholdCryptoError, DlShare};
use crate::rand::RNG;


#[derive(Clone, AsnType, Serializable)]
pub struct Bz03PublicKey {
    n: u16,
    k: u16,
    group: Group,
    y: GroupElement, //ECP2
    verificationKey: Vec<GroupElement>
}

impl Bz03PublicKey {
    pub fn new(group: &Group, n: usize, k: usize, y: &GroupElement, verificationKey: &Vec<GroupElement>) -> Self {
        Self { group: group.clone(), n:n as u16, k:k as u16, y:y.clone(), verificationKey:verificationKey.clone()}
    }

    pub fn get_order(&self) -> BigImpl {
        self.y.get_order()
    }

    pub fn get_group(&self) -> Group {
        self.group.clone()
    }

    pub fn get_threshold(&self) -> u16 {
        self.k
    }

    pub fn get_n(&self) -> u16  {
        self.n
    }
}

impl Encode for Bz03PublicKey {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.n.encode(sequence)?;
            self.k.encode(sequence)?;
            self.group.get_code().encode(sequence)?;
            self.y.to_bytes().encode(sequence)?;

            for i in 0..self.verificationKey.len() {
                self.verificationKey[i].to_bytes().encode(sequence)?;
            }

            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Bz03PublicKey {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let n = u16::decode(sequence)?;
            let k = u16::decode(sequence)?;

            let code = u8::decode(sequence)?;
            let group = Group::from_code(code);
            let y_b = Vec::<u8>::decode(sequence)?;
            let y = GroupElement::from_bytes(&y_b, &group, Option::Some(1));

            let mut verificationKey = Vec::<GroupElement>::new();
            for i in 0..n {
                let bytes = Vec::<u8>::decode(sequence)?;
                verificationKey.push(GroupElement::from_bytes(&bytes, &group, Option::None));
            }

            Ok(Self{n, k, y, group, verificationKey})
        })
    }
}

impl PartialEq for Bz03PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.y.eq(&other.y) && self.verificationKey.eq(&other.verificationKey)
    }
}

#[derive(Clone, AsnType, Serializable)]
pub struct Bz03PrivateKey {
    id: u16,
    xi: BigImpl,
    pubkey: Bz03PublicKey
}

impl Bz03PrivateKey {
    pub fn new(id: u16, xi: &BigImpl, pubkey: &Bz03PublicKey) -> Self {
        Self {id, xi:xi.clone(), pubkey:pubkey.clone()}
    }

    pub fn get_public_key(&self) -> Bz03PublicKey {
        self.pubkey.clone()
    }

    pub fn get_order(&self) -> BigImpl {
        self.get_group().get_order()
    }

    pub fn get_group(&self) -> Group {
        self.pubkey.get_group()
    }

    pub fn get_threshold(&self) -> u16 {
        self.pubkey.get_threshold()
    }

    pub fn get_n(&self) -> u16  {
        self.pubkey.get_n()
    }
}


impl Encode for Bz03PrivateKey {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.id.encode(sequence)?;
            self.xi.to_bytes().encode(sequence)?;
            self.pubkey.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Bz03PrivateKey {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let id = u16::decode(sequence)?;
            let xi_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let pubkey = Bz03PublicKey::decode(sequence)?;
            let xi = BigImpl::from_bytes(&pubkey.group, &xi_bytes);

            Ok(Self {id, xi, pubkey})
        })
    }
}

impl PartialEq for Bz03PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.xi == other.xi && self.pubkey == other.pubkey
    }
}

#[derive(Clone, AsnType, Serializable)]
pub struct Bz03DecryptionShare{
    group: Group,
    id: u16,
    data: GroupElement
}

impl DlShare for Bz03DecryptionShare {
    fn get_id(&self) -> u16 {
        self.id
    }

    fn get_data(&self) -> GroupElement {
        self.data.clone()
    }

    fn get_group(&self) -> Group {
        self.group.clone()
    }
}

impl Encode for Bz03DecryptionShare {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.group.get_code().encode(sequence)?;
            self.id.encode(sequence)?;
            self.data.to_bytes().encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Bz03DecryptionShare {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let group = Group::from_code(u8::decode(sequence)?);
            let id = u16::decode(sequence)?;
            let bytes = Vec::<u8>::decode(sequence)?;
            let data = GroupElement::from_bytes(&bytes, &group, Option::None);
            Ok(Self {group, id, data})
        })
    }
}

impl PartialEq for Bz03DecryptionShare {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.data == other.data
    }
}

#[derive(Clone, AsnType, Serializable)]
pub struct Bz03Ciphertext {
    label: Vec<u8>,
    msg: Vec<u8>,
    c_k: Vec<u8>,
    u: GroupElement, //ECP2
    hr: GroupElement
}

impl Encode for Bz03Ciphertext {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.u.get_group().get_code().encode(sequence)?;
            self.label.encode(sequence)?;
            self.msg.encode(sequence)?;
            self.c_k.encode(sequence)?;
            self.u.to_bytes().encode(sequence)?;
            self.hr.to_bytes().encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl  Decode for Bz03Ciphertext {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let group = Group::from_code(u8::decode(sequence)?);
            let label:Vec<u8> = Vec::<u8>::decode(sequence)?;
            let msg:Vec<u8> = Vec::<u8>::decode(sequence)?;
            let c_k:Vec<u8> = Vec::<u8>::decode(sequence)?;

            let u_b = Vec::<u8>::decode(sequence)?;
            let u = GroupElement::from_bytes(&u_b, &group, Option::Some(1)); 

            let hr_b = Vec::<u8>::decode(sequence)?;
            let hr = GroupElement::from_bytes(&hr_b, &group, Option::Some(0)); 

            Ok(Self {label, msg, u, c_k, hr})
        })
    }
}

impl PartialEq for Bz03Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        self.label == other.label && self.msg == other.msg && self.c_k == other.c_k && self.u == other.u && self.hr == other.hr
    }
}

pub struct Bz03ThresholdCipher {
    g:u8
}

pub struct Bz03Params {
}

impl Bz03ThresholdCipher {
    pub fn encrypt(msg: &[u8], label: &[u8], pk: &Bz03PublicKey, params: &mut ThresholdCipherParams) -> Bz03Ciphertext {
        let r = BigImpl::new_rand(&pk.get_group(), &pk.get_group().get_order(), &mut params.rng);
        let mut u = GroupElement::new_ecp2(&pk.get_group());
        u.pow(&r);

        let mut rY = pk.y.clone();
        rY.pow(&r);

        let k = gen_symm_key(&mut params.rng);
        let key = Key::from_slice(&k);
        let cipher = ChaCha20Poly1305::new(key);
        let encryption: Vec<u8> = cipher
            .encrypt(Nonce::from_slice(&rY.to_bytes()[0..12]),  msg)
            .expect("encryption failure");
            
        let c_k = xor(G(&rY), (k).to_vec());

        let mut hr = H(&u, &encryption);
        hr.pow(&r);

        let c = Bz03Ciphertext{label:label.to_vec(), msg:encryption, c_k:c_k.to_vec(), u:u, hr:hr};
        c
    }

    pub fn verify_ciphertext(ct: &Bz03Ciphertext, _pk: &Bz03PublicKey) -> Result<bool, ThresholdCryptoError> {
        let h = H(&ct.u, &ct.msg);

        GroupElement::ddh(&ct.u, &h, &GroupElement::new_ecp2(&ct.u.get_group()), &ct.hr)
    }

    pub fn verify_share(share: &Bz03DecryptionShare, ct: &Bz03Ciphertext, pk: &Bz03PublicKey) -> Result<bool, ThresholdCryptoError> {
        GroupElement::ddh(&share.data, &GroupElement::new(&share.group), &ct.u, &pk.verificationKey[(&share.id - 1) as usize])
    }

    pub fn partial_decrypt(ct: &Bz03Ciphertext, sk: &Bz03PrivateKey, _params: &mut ThresholdCipherParams) -> Bz03DecryptionShare {
        let mut u = ct.u.clone();
        u.pow(&sk.xi);

        Bz03DecryptionShare {group: u.get_group(), id:sk.id, data: u}
    }

    pub fn assemble(shares: &Vec<Bz03DecryptionShare>, ct: &Bz03Ciphertext) -> Vec<u8> {
        let rY = interpolate(shares);
        
        let k = xor(G(&rY), ct.c_k.clone());
        let key = Key::from_slice(&k);
        let cipher = ChaCha20Poly1305::new(key);
        let msg = cipher
            .decrypt(Nonce::from_slice(&rY.to_bytes()[0..12]), ct.msg.as_ref())
            .expect("decryption failure");

        msg
    }

}

fn H(g: &GroupElement, m: &Vec<u8>) -> GroupElement {
    let bytes  = g.to_bytes();
    
    let mut h = HASH256::new();
    h.process_array(&[&bytes[..], &m[..]].concat());

    let h = [&vec![0;big::MODBYTES - 32][..], &h.hash()[..]].concat();

    let mut s = BigImpl::from_bytes(&g.get_group(),&h);
    s.rmod(&g.get_group().get_order());

    let mut res = GroupElement::new(&g.get_group());
    res.pow(&s);
    res
}

// hash ECP to bit string
fn G(x: &GroupElement) -> Vec<u8> {
    let res = x.to_bytes();

    let mut h = HASH256::new();
    h.process_array(&res);
    
    let r = h.hash().to_vec();
    r
}
