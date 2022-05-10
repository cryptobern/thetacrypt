#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]

use derive::{PublicKey, Serializable, DlShare, Share, PrivateKey};
use mcore::{hash256::HASH256};
use rasn::{AsnType, Encode, Decode};

use crate::{dl_schemes::{DlDomain, DlShare, common::interpolate, dl_groups::{dl_group::DlGroup, pairing::PairingEngine}, keygen::{DlKeyGenerator, DlPrivateKey, DlScheme}}, interface::{PrivateKey, PublicKey, Share, ThresholdSignature, Serializable, ThresholdSignatureParams}, unwrap_keys, rand::RNG};
use crate::dl_schemes::bigint::*;

pub struct Bls04ThresholdSignature<PE: PairingEngine> {
    g: PE
}

#[derive(Clone, AsnType, PublicKey)]
pub struct Bls04PublicKey<PE: PairingEngine> {
    t: u32,
    y: PE,
    verificationKey:Vec<PE>
}  

impl <PE: PairingEngine> Encode for Bls04PublicKey<PE> {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.t.encode(sequence)?;
            self.y.encode(sequence)?;
            self.verificationKey.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl <PE: PairingEngine>  Decode for Bls04PublicKey<PE> {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let t = u32::decode(sequence)?;
            let y = PE::decode(sequence)?;
            let verificationKey = Vec::<PE>::decode(sequence)?;

            Ok(Self{t, y, verificationKey})
        })
    }
}


#[derive(Clone, PrivateKey, AsnType)]
pub struct Bls04PrivateKey<PE: PairingEngine> {
    id: u32,
    xi: BigImpl,
    pubkey: Bls04PublicKey<PE>
}

impl <PE: PairingEngine> Encode for Bls04PrivateKey<PE> {
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

impl <PE: PairingEngine>  Decode for Bls04PrivateKey<PE> {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let id = u32::decode(sequence)?;
            let xi_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let pubkey = Bls04PublicKey::<PE>::decode(sequence)?;
            let xi = PE::BigInt::from_bytes(&xi_bytes);

            Ok(Self {id, xi, pubkey})
        })
    }
}


impl<PE:PairingEngine> Bls04PrivateKey<PE> {
    pub fn new(id: u32, xi: &BigImpl, pubkey: &Bls04PublicKey<PE>) -> Self {
        Self {id, xi:xi.clone(), pubkey:pubkey.clone()}
    }
}

impl<PE:PairingEngine> PartialEq for Bls04PrivateKey<PE> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.xi == other.xi && self.pubkey == other.pubkey
    }
}

impl<PE:PairingEngine> Bls04PublicKey<PE> {
    pub fn new(t:u32, y: &PE, verificationKey: &Vec<PE>) -> Self {
        Self {t:t.clone(), y:y.clone(), verificationKey:verificationKey.clone()}
    }
}

impl<PE:PairingEngine> PartialEq for Bls04PublicKey<PE> {
    fn eq(&self, other: &Self) -> bool {
        self.y.equals(&other.y) && self.verificationKey.eq(&other.verificationKey)
    }
}

#[derive(Clone, AsnType, Share)]
pub struct Bls04SignatureShare<PE: PairingEngine> {
    id:u32,
    label:Vec<u8>,
    data:PE::G2
}

impl <PE:PairingEngine> DlShare<PE::G2> for Bls04SignatureShare<PE> {
    fn get_data(&self) -> PE::G2 {
        self.data.clone()
    }
}

impl <PE: PairingEngine> Encode for Bls04SignatureShare<PE> {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.id.encode(sequence)?;
            self.label.encode(sequence)?;
            self.data.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl <PE: PairingEngine>  Decode for Bls04SignatureShare<PE> {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let id = u32::decode(sequence)?;
            let label = Vec::<u8>::decode(sequence)?;
            let data = PE::G2::decode(sequence)?;
            Ok(Self {id, label, data})
        })
    }
}

impl<PE:PairingEngine> PartialEq for Bls04SignatureShare<PE> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.label == other.label && self.data == other.data
    }
}

#[derive(Clone, AsnType, Serializable)]
pub struct Bls04SignedMessage<PE: PairingEngine> {
    msg: Vec<u8>,
    sig: PE::G2
}

impl<PE: PairingEngine> Bls04SignedMessage<PE> {
    pub fn get_sig(&self) -> PE::G2 { self.sig.clone() }
}

impl <PE: PairingEngine> Encode for Bls04SignedMessage<PE> {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.msg.encode(sequence)?;
            self.sig.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl <PE: PairingEngine>  Decode for Bls04SignedMessage<PE> {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let msg:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let sig = PE::G2::decode(sequence)?;

            Ok(Self {msg, sig})
        })
    }
}

impl<PE:PairingEngine> PartialEq for Bls04SignedMessage<PE> {
    fn eq(&self, other: &Self) -> bool {
        self.msg == other.msg && self.sig == other.sig
    }
}

impl<PE: PairingEngine> ThresholdSignature for Bls04ThresholdSignature<PE> {
    type TSig = Bls04SignedMessage<PE>;

    type TPubKey = Bls04PublicKey<PE>;

    type TPrivKey = Bls04PrivateKey<PE>;

    type TShare = Bls04SignatureShare<PE>;

    fn verify(sig: &Self::TSig, pk: &Self::TPubKey) -> bool {
        PE::ddh(&H::<PE::G2>(&sig.msg), &pk.y ,&sig.sig, &PE::new())
    }

    fn partial_sign(msg: &[u8], label: &[u8], sk: &Self::TPrivKey, _params: &mut ThresholdSignatureParams) -> Self::TShare {
        let mut data = H::<PE::G2>(&msg);
        data.pow(&sk.xi);

        Bls04SignatureShare{ id: sk.id, label:label.to_vec(), data:data }
    }

    fn verify_share(share: &Self::TShare, msg: &[u8], pk: &Self::TPubKey) -> bool {
        PE::ddh(&H::<PE::G2>(&msg), &pk.verificationKey[(share.id - 1) as usize], &share.data, &PE::new())
    }

    fn assemble(shares: &Vec<Self::TShare>, msg: &[u8], _pk: &Self::TPubKey) -> Self::TSig {
        let sig = interpolate(&shares);
        Bls04SignedMessage{sig:sig, msg:msg.to_vec() } 
    }
}

impl<D:DlDomain> Bls04ThresholdSignature<D> {
    pub fn generate_keys(k: usize, n: usize, domain: D, rng: &mut RNG) -> Vec<Bls04PrivateKey<D>> {
        let keys = DlKeyGenerator::generate_keys(k, n, rng, &DlScheme::BLS04(domain));
        unwrap_keys!(keys, DlPrivateKey::BLS04)
    }
}

fn H<G: DlGroup>(m: &[u8]) -> G {
    let q = G::get_order();

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
            hash.process_array(&[&g[..], &(i.to_ne_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    let mut res = G::BigInt::from_bytes(&buf);
    res.rmod(&G::get_order());

    G::new_pow_big(&res)
}