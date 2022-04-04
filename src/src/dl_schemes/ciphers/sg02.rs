#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use derive::{PublicKey, PrivateKey, Ciphertext, Share};
use mcore::hash256::*;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; 
use chacha20poly1305::aead::{Aead, NewAead};
use rasn::types::{Integer, BitString};
use rasn::{Encode, AsnType, Decode};
use rasn::Encoder;
use rasn::der::{encode, decode};

use crate::dl_schemes::common::gen_symm_key;
use crate::dl_schemes::common::interpolate;
use crate::dl_schemes::common::xor;
use crate::dl_schemes::dl_groups::dl_group::*;
use crate::dl_schemes::keygen::{DlKeyGenerator, DlPrivateKey, DlScheme};
use crate::rand::{RNG, RngAlgorithm};
use crate::{interface::*, unwrap_keys};
use crate::interface::PrivateKey;
use crate::interface::PublicKey;
use crate::interface::Share;
use crate::interface::ThresholdCipher;
use crate::bigint::*;

use crate::dl_schemes::{DlDomain, DlShare};

pub struct Sg02ThresholdCipher<G: DlGroup> {
    g: G
}

#[derive(Clone, PublicKey, AsnType)]
pub struct Sg02PublicKey<G: DlGroup> {
    y: G,
    verificationKey: Vec<G>,
    g_bar: G
}

impl <G:DlGroup> Encode for Sg02PublicKey<G> {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        todo!()
    }
}

impl <G:DlGroup> Decode for Sg02PublicKey<G> {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        todo!()
    }
}

#[derive(Clone, PrivateKey, AsnType)]
pub struct Sg02PrivateKey<G: DlGroup> {
    id: usize,
    xi: BigImpl,
    pubkey: Sg02PublicKey<G>,
}

impl <G:DlGroup> Encode for Sg02PrivateKey<G> {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        todo!()
    }
}

impl <G:DlGroup> Decode for Sg02PrivateKey<G> {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        todo!()
    }
}

impl<G: DlGroup> Sg02PrivateKey<G> {
    pub fn new(id: usize, xi: &BigImpl, pubkey: &Sg02PublicKey<G>) -> Self {
        Self {id, xi:xi.clone(), pubkey:pubkey.clone()}
    }
}

#[derive(Clone, AsnType, Ciphertext)]
pub struct Sg02Ciphertext<G: DlGroup> {
    label: Vec<u8>,
    msg: Vec<u8>,
    u: G,
    u_bar: G,
    e: BigImpl,
    f: BigImpl,
    c_k: Vec<u8>,
}

impl <G:DlGroup> Encode for Sg02Ciphertext<G> {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        todo!()
    }
}

impl <G:DlGroup> Decode for Sg02Ciphertext<G> {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        todo!()
    }
}

#[derive(Clone, AsnType, Share)]
pub struct Sg02DecryptionShare<G: DlGroup>  {
    id: usize,
    label: Vec<u8>,
    data: G,
    ei: BigImpl,
    fi: BigImpl,
}

impl<G: DlGroup> Sg02PublicKey<G> {
    pub fn new(y: &G, verificationKey: &Vec<G>, g_bar:&G) -> Self {
        Self {y:y.clone(), verificationKey:verificationKey.clone(), g_bar:g_bar.clone()}
    }
}

impl<G:DlGroup> Encode for Sg02DecryptionShare<G> {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |encoder| {
            self.id.encode(encoder)?;
            self.label.encode(encoder)?;
            self.data.to_bytes().encode(encoder)?;
            self.ei.to_bytes().encode(encoder)?;
            self.fi.to_bytes().encode(encoder)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl<G: DlGroup>Decode for Sg02DecryptionShare<G> {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |decoder| {
            let id = usize::decode(decoder)?;
            let label:Vec<u8> = BitString::decode(decoder)?.into();
            let data_bytes:Vec<u8> = BitString::decode(decoder)?.into();
            let ei_bytes:Vec<u8> = BitString::decode(decoder)?.into();
            let fi_bytes:Vec<u8> = BitString::decode(decoder)?.into();

            let data = G::from_bytes(&data_bytes);
            let ei = G::BigInt::from_bytes(&ei_bytes);
            let fi = G::BigInt::from_bytes(&fi_bytes);
            Ok(Self {id, label, data, ei, fi})
        })
    }
}

impl<G: DlGroup> DlShare<G> for Sg02DecryptionShare<G> {
    fn get_data(&self) -> G {
        self.data.clone()
    }
}


impl<G:DlGroup> ThresholdCipher for Sg02ThresholdCipher<G> {
    type TPubKey = Sg02PublicKey<G>;
    type TPrivKey = Sg02PrivateKey<G>;
    type CT = Sg02Ciphertext<G>;
    type TShare = Sg02DecryptionShare<G>;

    fn encrypt(msg: &[u8], label: &[u8], pk: &Sg02PublicKey<G>, params: &mut ThresholdCipherParams) -> Self::CT {
        let r = G::BigInt::new_rand(&G::get_order(), &mut params.rng);
        let mut u = G::new();
        u.pow(&r);

        let mut rY = pk.y.clone();
        rY.pow(&r);

        let k = gen_symm_key(&mut params.rng);
        let key = Key::from_slice(&k);
        let cipher = ChaCha20Poly1305::new(key);
        let encryption: Vec<u8> = cipher
            .encrypt(Nonce::from_slice(&rY.to_bytes()[0..12]),  msg)
            .expect("Failed to encrypt plaintext");
        
        let c_k = xor(H(&rY), (k).to_vec());
      
        let s = G::BigInt::new_rand(&G::get_order(), &mut params.rng);
        let mut w = G::new();
        w.pow(&s);

        let mut w_bar = pk.g_bar.clone();
        w_bar.pow(&s);

        let mut u_bar = pk.g_bar.clone();
        u_bar.pow(&r);

        let e = H1(&c_k, &label, &u, &w, &u_bar, &w_bar);

        let mut f = s.clone();
        f.add(&BigImpl::rmul(&e, &r, &G::get_order()));
        f.rmod(&G::get_order());

        let c = Sg02Ciphertext{label:label.to_vec(), msg:encryption, c_k:c_k.to_vec(), u:u, u_bar:u_bar, e:e, f:f};
        c
    }

    fn verify_ciphertext(ct: &Self::CT, pk: &Self::TPubKey) -> bool {
        let mut w = G::new();
        w.pow(&ct.f);

        let mut rhs = ct.u.clone();
        rhs.pow(&ct.e);

        w.div(&rhs);

        let mut w_bar = pk.g_bar.clone();
        w_bar.pow(&ct.f);

        let mut rhs = ct.u_bar.clone();
        rhs.pow(&ct.e);

        w_bar.div(&rhs);

        let e2 = H1(&ct.c_k, &ct.label, &ct.u, &w, &ct.u_bar, &w_bar);

        ct.e.equals(&e2)
    }

    fn verify_share(share: &Self::TShare, ct: &Self::CT, pk: &Self::TPubKey) -> bool {
        let mut ui_bar = ct.u.clone();
        ui_bar.pow(&share.fi);

        let mut rhs = share.data.clone();
        rhs.pow(&share.ei);

        ui_bar.div(&rhs);

        let mut hi_bar = G::new();
        hi_bar.pow(&share.fi);

        let mut rhs = pk.verificationKey[(share.get_id() -1) as usize].clone();
        rhs.pow(&share.ei);

        hi_bar.div(&rhs);

        let ei2 = H2(&share.data, &ui_bar, &hi_bar);

        share.ei.equals(&ei2)
    }

    fn partial_decrypt(ct: &Self::CT, sk: &Self::TPrivKey, params: &mut ThresholdCipherParams) -> Self::TShare {
        let mut data = ct.u.clone();
        data.pow(&sk.xi);

        let si = G::BigInt::new_rand(&G::get_order(), &mut params.rng);

        let mut ui_bar = ct.u.clone();
        ui_bar.pow(&si);

        let mut hi_bar = G::new();
        hi_bar.pow(&si);

        let ei = H2(&data, &ui_bar, &hi_bar);
        let mut fi = si.clone();
        fi.add(&BigImpl::rmul(&sk.xi, &ei, &G::get_order()));
        fi.rmod(&G::get_order());

        Sg02DecryptionShare { id:sk.id.clone(), data:data, label:ct.label.clone(), ei:ei, fi:fi}
    }

    fn assemble(shares: &Vec<Self::TShare>, ct: &Self::CT) -> Vec<u8> {
        let rY = interpolate(shares);
        let k = xor(H(&rY), ct.c_k.clone());
        let key = Key::from_slice(&k);
        let cipher = ChaCha20Poly1305::new(key);
        let msg = cipher
            .decrypt(Nonce::from_slice(&rY.to_bytes()[0..12]), ct.msg.as_ref())
            .expect("Failed to decrypt ciphertext. Make sure you have enough valid decryption shares");
        
        msg
    }
}

impl<D:DlDomain> Sg02ThresholdCipher<D> {
    pub fn generate_keys(k: usize, n: usize, domain: D, rng: &mut RNG) -> Vec<Sg02PrivateKey<D>> {
        let keys = DlKeyGenerator::generate_keys(k, n, rng, &DlScheme::SG02(domain));
        unwrap_keys!(keys, DlPrivateKey::SG02)
    }
}

// hash ECP to bit string
fn H<G: DlGroup>(x: &G) -> Vec<u8> {
    let mut h = HASH256::new();
    let buf = x.to_bytes();

    h.process_array(&buf);
    
    let r = h.hash().to_vec();
    r
}

fn H1<G:DlGroup>(m1: &[u8], m2:&[u8], g1: &G, g2: &G, g3: &G, g4: &G) -> BigImpl {
    let mut buf:Vec<u8> = Vec::new();
    let q = G::get_order();

    buf = [&buf[..], &m1[..]].concat();
    buf = [&buf[..], &m2[..]].concat();
    buf = [&buf[..], &g1.to_bytes()[..]].concat();
    buf = [&buf[..], &g2.to_bytes()[..]].concat();
    buf = [&buf[..], &g3.to_bytes()[..]].concat();
    buf = [&buf[..], &g4.to_bytes()[..]].concat();

    let mut hash = HASH256::new();
    hash.process_array(&buf);
    let h = hash.hash();

    buf = Vec::new();
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

    res
}

fn H2<G: DlGroup>(g1: &G, g2: &G, g3: &G) -> BigImpl {
    let mut buf:Vec<u8> = Vec::new();
    let q = G::get_order();

    buf = [&buf[..], &g1.to_bytes()[..]].concat();
    buf = [&buf[..], &g2.to_bytes()[..]].concat();
    buf = [&buf[..], &g3.to_bytes()[..]].concat();

    let mut hash = HASH256::new();
    hash.process_array(&buf);
    let h = hash.hash();

    buf = Vec::new();
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

    res
}