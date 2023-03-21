#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]

use derive::{PublicKey, PrivateKey, Serializable, DlShare};
use mcore::hash256::HASH256;
use rasn::{AsnType, Encode, Decode};

use crate::{group::{GroupElement}, dl_schemes::{common::interpolate}, interface::{ThresholdSignatureParams, DlShare, Serializable, ThresholdCryptoError}};
use crate::interface::ThresholdScheme; use  crate::group::Group;
use crate::dl_schemes::bigint::BigImpl;
pub struct Bls04ThresholdSignature {
    g: GroupElement
}

#[derive(Clone, Debug, AsnType, Serializable)]
pub struct Bls04PublicKey {
    group: Group,
    n: u16,
    k: u16,
    y: GroupElement,
    verification_key:Vec<GroupElement>
}  

impl Bls04PublicKey {
    pub fn new(group: &Group, n:usize, k:usize, y: &GroupElement, verification_key: &Vec<GroupElement>) -> Self {
        Self {group:group.clone(), n:n as u16, k:k as u16, y:y.clone(), verification_key:verification_key.clone()}
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

impl PartialEq for Bls04PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n && self.k == other.k && self.y == other.y && self.verification_key.eq(&other.verification_key)
    }
}

impl Encode for Bls04PublicKey {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.get_group().get_code().encode(sequence)?;
            self.n.encode(sequence)?;
            self.k.encode(sequence)?;
            self.y.to_bytes().encode(sequence)?;
            for i in 0..self.verification_key.len() {
                self.verification_key[i].to_bytes().encode(sequence)?;
            }
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Bls04PublicKey {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let group = Group::from_code(u8::decode(sequence)?);
            let n = u16::decode(sequence)?;
            let k = u16::decode(sequence)?;
            let y_b = Vec::<u8>::decode(sequence)?;
            let mut verification_key = Vec::new();

            for _i in 0..n {
                let bytes = Vec::<u8>::decode(sequence)?;
                verification_key.push(GroupElement::from_bytes(&bytes, &group, Option::None));
            }

            let y = GroupElement::from_bytes(&y_b, &group, Option::Some(0));

            Ok(Self{group, n, k, y, verification_key})
        })
    }
}


#[derive(Clone, Debug, AsnType, Serializable, PartialEq)]
pub struct Bls04PrivateKey {
    id: u16,
    xi: BigImpl,
    pubkey: Bls04PublicKey
}

impl Bls04PrivateKey {
    pub fn get_order(&self) -> BigImpl {
        self.pubkey.get_order()
    }

    pub fn get_id(&self) -> u16 {
        self.id
    }

    pub fn get_threshold(&self) -> u16 {
        self.pubkey.k
    }

    pub fn get_group(&self) -> Group {
        self.pubkey.get_group()
    }

    pub fn new(id:u16, xi: &BigImpl, pubkey: &Bls04PublicKey) -> Self {
        Self {id:id.clone(), xi:xi.clone(), pubkey:pubkey.clone()}
    }

    pub fn get_public_key(&self) -> Bls04PublicKey {
        self.pubkey.clone()
    }
}

impl Encode for Bls04PrivateKey {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.id.encode(sequence)?;
            self.xi.to_bytes().encode(sequence)?;
            self.pubkey.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Bls04PrivateKey {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let id = u16::decode(sequence)?;
            let xi_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let pubkey = Bls04PublicKey::decode(sequence)?;
            let xi = BigImpl::from_bytes(&pubkey.group, &xi_bytes);

            Ok(Self {id, xi, pubkey})
        })
    }
}

#[derive(Clone, AsnType, DlShare, Serializable, PartialEq)]
pub struct Bls04SignatureShare {
    group:Group,
    id:u16,
    label:Vec<u8>,
    data:GroupElement // ECP2
}

impl Bls04SignatureShare {
    pub fn get_label(&self) -> &[u8]{ &self.label }
    pub fn get_scheme(&self) -> ThresholdScheme { ThresholdScheme::Bls04 }
}

impl Encode for Bls04SignatureShare {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.group.get_code().encode(sequence)?;
            self.id.encode(sequence)?;
            self.label.encode(sequence)?;
            self.data.to_bytes().encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Bls04SignatureShare {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let group = Group::from_code(u8::decode(sequence)?);
            let id = u16::decode(sequence)?;
            let label = Vec::<u8>::decode(sequence)?;
            let bytes = Vec::<u8>::decode(sequence)?;

            let data = GroupElement::from_bytes(&bytes, &group, Option::Some(1));

            Ok(Self {group, id, label, data})
        })
    }
}

#[derive(Clone, AsnType, Serializable, PartialEq)]
pub struct Bls04Signature {
    group: Group,
    sig: GroupElement // ECP2
}

impl Bls04Signature {
    pub fn get_sig(&self) -> GroupElement { self.sig.clone() }
    pub fn get_group(&self) -> Group { self.group.clone() }
}

impl Encode for Bls04Signature {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.group.get_code().encode(sequence)?;
            self.sig.to_bytes().encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Bls04Signature {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let group = Group::from_code(u8::decode(sequence)?);
            let bytes = Vec::<u8>::decode(sequence)?;
            let sig = GroupElement::from_bytes(&bytes, &group, Option::Some(1));

            Ok(Self {group, sig})
        })
    }
}

impl Bls04ThresholdSignature {
    pub fn verify(sig: &Bls04Signature, pk: &Bls04PublicKey, msg:&[u8]) -> Result<bool, ThresholdCryptoError> {
        GroupElement::ddh(&H(&msg, &pk.get_group()), &pk.y ,&sig.sig, &GroupElement::new(&sig.get_group()))
    }

    pub fn partial_sign(msg: &[u8], label: &[u8], sk: &Bls04PrivateKey, _params: &mut ThresholdSignatureParams) -> Bls04SignatureShare {
        let data = H(&msg, &sk.get_group()).pow(&sk.xi);

        Bls04SignatureShare{ group:data.get_group().clone(), id: sk.id, label:label.to_vec(), data:data }
    }

    pub fn verify_share(share: &Bls04SignatureShare, msg: &[u8], pk: &Bls04PublicKey) -> Result<bool, ThresholdCryptoError> {
        GroupElement::ddh(&H(&msg, &share.get_group()), &pk.verification_key[(share.id - 1) as usize], &share.data, &GroupElement::new(&share.get_group()))
    }

    pub fn assemble(shares: &Vec<Bls04SignatureShare>, msg: &[u8], _pk: &Bls04PublicKey) -> Bls04Signature {
        let sig = interpolate(&shares);
        Bls04Signature{group: sig.get_group().clone(), sig:sig } 
    }
}

fn H(m: &[u8], group:&Group) -> GroupElement {
    let q = group.get_order();

    let mut hash = HASH256::new();
    hash.process_array(&m);
    let h = hash.hash();

    let mut buf = Vec::new();
    buf = [&buf[..], &h].concat();
    
    let nbits = q.nbytes()*8;
    
    if nbits > buf.len()*4 {
        let mut g:[u8;32];
        for i in 1..(((nbits - buf.len()*4)/buf.len()*8) as f64).ceil() as isize {
            g = h.clone();
            hash.process_array(&[&g[..], &(i.to_le_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    let mut res = BigImpl::from_bytes(&group, &buf);
    res.rmod(&group.get_order());

    GroupElement::new_pow_big_ecp2(&group, &res)
}