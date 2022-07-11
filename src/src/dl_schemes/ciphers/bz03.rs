#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; 
use chacha20poly1305::aead::{Aead, NewAead};
use derive::{PublicKey, PrivateKey, Share, DlShare, Ciphertext};
use mcore::bls12381::big;
use mcore::hash256::*;
use rasn::{AsnType, Tag, Encode, Decode};

use crate::dl_schemes::bigint::*;
use crate::dl_schemes::dl_groups::bls12381::Bls12381;
use crate::dl_schemes::dl_groups::dl_group::DlGroup;
use crate::dl_schemes::dl_groups::pairing::PairingEngine;
use crate::dl_schemes::{DlDomain, DlShare, common::*};
use crate::rand::RNG;


#[derive(Clone, PublicKey, AsnType)]
pub struct Bz03PublicKey {
    t: u32,
    y: PE::G2,
    verificationKey: Vec<PE>
}

impl<PE:PairingEngine> Encode for Bz03PublicKey<PE> {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.t.encode(sequence)?;
            self.y.encode(sequence)?;
            self.verificationKey.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl<PE:PairingEngine> Decode for Bz03PublicKey<PE> {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let t = u32::decode(sequence)?;
            let y = PE::G2::decode(sequence)?;
            let verificationKey = Vec::<PE>::decode(sequence)?;

            Ok(Self{t, y, verificationKey})
        })
    }
}

impl<PE:PairingEngine> PartialEq for Bz03PublicKey<PE> {
    fn eq(&self, other: &Self) -> bool {
        self.y.equals(&other.y) && self.verificationKey.eq(&other.verificationKey)
    }
}

#[derive(Clone, PrivateKey, AsnType)]
pub struct Bz03PrivateKey<PE: PairingEngine> {
    id: u32,
    xi: BigImpl,
    pubkey: Bz03PublicKey<PE>
}

impl<PE:PairingEngine> Encode for Bz03PrivateKey<PE> {
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

impl<PE:PairingEngine> Decode for Bz03PrivateKey<PE> {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let id = u32::decode(sequence)?;
            let xi_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let pubkey = Bz03PublicKey::<PE>::decode(sequence)?;
            let xi = PE::BigInt::from_bytes(&xi_bytes);

            Ok(Self {id, xi, pubkey})
        })
    }
}

impl<PE:PairingEngine> PartialEq for Bz03PrivateKey<PE> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.xi == other.xi && self.pubkey == other.pubkey
    }
}

#[derive(Clone, Share, DlShare, AsnType)]
pub struct Bz03DecryptionShare<G: DlGroup> {
    id: u32,
    data: G
}

impl<G:DlGroup> Encode for Bz03DecryptionShare<G> {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.id.encode(sequence)?;
            self.data.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl<G:DlGroup> Decode for Bz03DecryptionShare<G> {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let id = u32::decode(sequence)?;
            let data = G::decode(sequence)?;
            Ok(Self {id, data})
        })
    }
}

impl<G:DlGroup> PartialEq for Bz03DecryptionShare<G> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.data == other.data
    }
}

#[derive(Clone, Ciphertext, AsnType)]
pub struct Bz03Ciphertext<PE: PairingEngine> {
    label: Vec<u8>,
    msg: Vec<u8>,
    c_k: Vec<u8>,
    u: PE::G2,
    hr: PE
}

impl<PE:PairingEngine> Encode for Bz03Ciphertext<PE> {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.label.encode(sequence)?;
            self.msg.encode(sequence)?;
            self.c_k.encode(sequence)?;
            self.u.encode(sequence)?;
            self.hr.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl<PE:PairingEngine> Decode for Bz03Ciphertext<PE> {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let label:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let msg:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let c_k:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let u = PE::G2::decode(sequence)?;
            let hr = PE::decode(sequence)?;

            Ok(Self {label, msg, u, c_k, hr})
        })
    }
}

impl<PE:PairingEngine> PartialEq for Bz03Ciphertext<PE> {
    fn eq(&self, other: &Self) -> bool {
        self.label == other.label && self.msg == other.msg && self.c_k == other.c_k && self.u == other.u && self.hr == other.hr
    }
}

pub struct Bz03ThresholdCipher<PE: PairingEngine> {
    g: PE
}

pub struct Bz03Params {
}

impl<PE:PairingEngine> Bz03PrivateKey<PE> {
    pub fn new(id: u32, xi: &BigImpl, pubkey: &Bz03PublicKey<PE>) -> Self {
        Self {id, xi:xi.clone(), pubkey:pubkey.clone()}
    }
}

impl<PE:PairingEngine> Bz03PublicKey<PE> {
    pub fn new(t: u32, y: &PE::G2, verificationKey: &Vec<PE>) -> Self {
        Self { t:t.clone(), y:y.clone(), verificationKey:verificationKey.clone()}
    }
}

impl<PE: PairingEngine> ThresholdCipher for Bz03ThresholdCipher<PE> {
    type CT = Bz03Ciphertext<PE>;

    type TPubKey = Bz03PublicKey<PE>;

    type TPrivKey = Bz03PrivateKey<PE>;

    type TShare = Bz03DecryptionShare<PE::G2>;

    fn encrypt(msg: &[u8], label: &[u8], pk: &Self::TPubKey, params: &mut ThresholdCipherParams) -> Self::CT {
        let r = PE::BigInt::new_rand(&PE::G2::get_order(), &mut params.rng);
        let mut u = PE::G2::new();
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

        let mut hr = H::<PE::G2, PE>(&u, &encryption);
        hr.pow(&r);

        let c = Bz03Ciphertext{label:label.to_vec(), msg:encryption, c_k:c_k.to_vec(), u:u, hr:hr};
        c
    }

    fn verify_ciphertext(ct: &Self::CT, _pk: &Self::TPubKey) -> bool {
        let h = H::<PE::G2, PE>(&ct.u, &ct.msg);

        PE::ddh(&ct.u, &h, &PE::G2::new(), &ct.hr)
    }

    fn verify_share(share: &Self::TShare, ct: &Self::CT, pk: &Self::TPubKey) -> bool {
        PE::ddh(&share.data, &PE::new(), &ct.u, &pk.verificationKey[(&share.id - 1) as usize])
    }

    fn partial_decrypt(ct: &Self::CT, sk: &Self::TPrivKey, _params: &mut ThresholdCipherParams) -> Self::TShare {
        let mut u = ct.u.clone();
        u.pow(&sk.xi);

        Bz03DecryptionShare {id:sk.id, data: u}
    }

    fn assemble(shares: &Vec<Self::TShare>, ct: &Self::CT) -> Vec<u8> {
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

impl<D:DlDomain> Bz03ThresholdCipher<D> {
    pub fn generate_keys(k: usize, n: usize, domain: D, rng: &mut RNG) -> Vec<Bz03PrivateKey<D>> {
        let keys = DlKeyGenerator::generate_keys(k, n, rng, &DlScheme::BZ03(domain));
        unwrap_keys!(keys, DlPrivateKey::BZ03)
    }
}

fn H<G1: DlGroup, G2: DlGroup>(g: &G1, m: &Vec<u8>) -> G2 {
    let bytes  = g.to_bytes();
    
    let mut h = HASH256::new();
    h.process_array(&[&bytes[..], &m[..]].concat());

    let h = [&vec![0;big::MODBYTES - 32][..], &h.hash()[..]].concat();

    let mut s = G2::BigInt::from_bytes(&h);
    s.rmod(&G2::get_order());

    let mut res = G2::new();
    res.pow(&s);
    res
}

// hash ECP to bit string
fn G<G: DlGroup>(x: &G) -> Vec<u8> {
    let res = x.to_bytes();

    let mut h = HASH256::new();
    h.process_array(&res);
    
    let r = h.hash().to_vec();
    r
}
