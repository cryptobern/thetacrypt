#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use derive::{DlShare, Share, PrivateKey, PublicKey};
use mcore::{hash256::HASH256};
use rasn::{AsnType, Encode, Decode};

use crate::dl_schemes::common::interpolate;
use crate::dl_schemes::keygen::{DlKeyGenerator, DlPrivateKey, DlScheme};
use crate::rand::RNG;
use crate::{dl_schemes::bigint::*, unwrap_keys};
use crate::dl_schemes::{DlDomain, DlShare};
use crate::{
    dl_schemes::dl_groups::{dl_group::DlGroup},
    interface::{PrivateKey, PublicKey, Share, ThresholdCoin},
};

pub struct Cks05ThresholdCoin<G: DlGroup> {
    g: G,
}

#[derive(AsnType, PublicKey, Clone)]
pub struct Cks05PublicKey<G: DlGroup> {
    y: G,
    verificationKey: Vec<G>
}

impl<G: DlGroup> Cks05PublicKey<G> {
    pub fn new(y: &G, verificationKey: &Vec<G>) -> Self {
        Self {
            y: y.clone(),
            verificationKey: verificationKey.clone()
        }
    }
}

impl<G: DlGroup> Encode for Cks05PublicKey<G> {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.y.encode(sequence)?;
            self.verificationKey.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl<G: DlGroup> Decode for Cks05PublicKey<G> {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let y: G = G::decode(sequence)?;
            let verificationKey = Vec::<G>::decode(sequence)?;

            Ok(Self{y, verificationKey})
        })
    }
}

impl<G:DlGroup> PartialEq for Cks05PublicKey<G> {
    fn eq(&self, other: &Self) -> bool {
        self.verificationKey.eq(&other.verificationKey) &&  self.y.equals(&other.y) 
    }
}

#[derive(AsnType, PrivateKey, Clone)]
pub struct Cks05PrivateKey<G: DlGroup> {
    id: u32,
    xi: BigImpl,
    pubkey: Cks05PublicKey<G>,
}

impl<G: DlGroup> Cks05PrivateKey<G> {
    pub fn new(id: u32, xi: &BigImpl, pubkey: &Cks05PublicKey<G>) -> Self {
        Self {
            id,
            xi: xi.clone(),
            pubkey: pubkey.clone(),
        }
    }
}

impl<G: DlGroup> Encode for Cks05PrivateKey<G> {
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

impl<G: DlGroup> Decode for Cks05PrivateKey<G> {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let id = u32::decode(sequence)?;
            let xi_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let pubkey = Cks05PublicKey::<G>::decode(sequence)?;
            let xi = G::BigInt::from_bytes(&xi_bytes);

            Ok(Self {id, xi, pubkey})
        })
    }
}

impl<G: DlGroup> PartialEq for Cks05PrivateKey<G> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.xi == other.xi && self.pubkey == other.pubkey
    }
}

#[derive(Share, DlShare, AsnType, Clone)]
pub struct Cks05CoinShare<G: DlGroup> {
    id: u32,
    data: G,
    c: BigImpl,
    z: BigImpl,
}

impl<G: DlGroup> Encode for Cks05CoinShare<G> {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.id.encode(sequence)?;
            self.data.encode(sequence)?;
            self.c.to_bytes().encode(sequence)?;
            self.z.to_bytes().encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl<G: DlGroup> Decode for Cks05CoinShare<G> {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let id = u32::decode(sequence)?;
            let data = G::decode(sequence)?;
            let c_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let z_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();

            let c = G::BigInt::from_bytes(&c_bytes);
            let z = G::BigInt::from_bytes(&z_bytes);
            Ok(Self {id, data, c, z})
        })
    }
}

impl<G: DlGroup> PartialEq for Cks05CoinShare<G> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.data.equals(&other.data) && self.c.equals(&other.c) && self.z.equals(&other.z)
    }
}

impl<G: DlGroup> ThresholdCoin for Cks05ThresholdCoin<G> {
    type TPubKey = Cks05PublicKey<G>;

    type TPrivKey = Cks05PrivateKey<G>;

    type TShare = Cks05CoinShare<G>;

    fn create_share(name: &[u8], sk: &Self::TPrivKey, rng: &mut RNG) -> Self::TShare {
        let q = G::get_order();

        let c_bar = H::<G>(name);
        let mut data = c_bar.clone();
        data.pow(&sk.xi);

        let s = G::BigInt::new_rand(&q, rng);

        let mut h = G::new();
        h.pow(&s);

        let mut h_bar = c_bar.clone();
        h_bar.pow(&s);

        let c = H1(
            &G::new(),
            &sk.pubkey.verificationKey[(sk.id - 1) as usize],
            &h,
            &c_bar,
            &data,
            &h_bar,
        );

        let mut z = s.clone();
        z.add(&BigImpl::rmul(&c, &sk.xi, &q));
        z.rmod(&q);

        Cks05CoinShare { id: sk.id, data, c, z,}
    }

    fn verify_share(share: &Self::TShare, name: &[u8], pk: &Self::TPubKey) -> bool {
        let c_bar = H::<G>(name);

        let mut h = G::new();
        h.pow(&share.z);

        let mut rhs = pk.verificationKey[(share.id -1) as usize].clone();
        rhs.pow(&share.c);

        h.div(&rhs);

        let mut h_bar = c_bar.clone();
        h_bar.pow(&share.z);

        let mut rhs = share.data.clone();
        rhs.pow(&share.c);

        h_bar.div(&rhs);

        let c = H1(
            &G::new(),
            &pk.verificationKey[(share.id - 1) as usize],
            &h,
            &c_bar,
            &share.data,
            &h_bar,
        );

        share.c.equals(&c)
    }

    fn assemble(shares: &Vec<Self::TShare>) -> u8 {
        let coin = interpolate(shares);
        H2(&coin)
    }
}

impl<D:DlDomain> Cks05ThresholdCoin<D> {
    pub fn generate_keys(k: usize, n: usize, domain: D, rng: &mut RNG) -> Vec<Cks05PrivateKey<D>> {
        let keys = DlKeyGenerator::generate_keys(k, n, rng, &DlScheme::CKS05(domain));
        unwrap_keys!(keys, DlPrivateKey::CKS05)
    }
}


fn H<G: DlGroup>(name: &[u8]) -> G {
    let mut buf: Vec<u8> = Vec::new();
    let q = G::get_order();

    buf = [&buf[..], &name[..]].concat();

    let mut hash = HASH256::new();
    hash.process_array(&buf);
    let h = hash.hash();

    buf = Vec::new();
    buf = [&buf[..], &h].concat();

    let nbits = q.nbytes() * 8;

    if nbits > buf.len() * 4 {
        let mut g: [u8; 32];
        for i in 1..(((nbits - buf.len() * 4) / buf.len() * 8) as f64).ceil() as isize {
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

fn H1<G: DlGroup>(g1: &G, g2: &G, g3: &G, g4: &G, g5: &G, g6: &G) -> BigImpl {
    let mut buf: Vec<u8> = Vec::new();
    let q = G::get_order();

    buf = [&buf[..], &g1.to_bytes()[..]].concat();
    buf = [&buf[..], &g2.to_bytes()[..]].concat();
    buf = [&buf[..], &g3.to_bytes()[..]].concat();
    buf = [&buf[..], &g4.to_bytes()[..]].concat();
    buf = [&buf[..], &g5.to_bytes()[..]].concat();
    buf = [&buf[..], &g6.to_bytes()[..]].concat();

    let mut hash = HASH256::new();
    hash.process_array(&buf);
    let h = hash.hash();

    buf = Vec::new();
    buf = [&buf[..], &h].concat();

    let nbits = q.nbytes() * 8;

    if nbits > buf.len() * 4 {
        let mut g: [u8; 32];
        for i in 1..(((nbits - buf.len() * 4) / buf.len() * 8) as f64).ceil() as isize {
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

fn H2<G: DlGroup>(g: &G) -> u8 {
    let mut buf: Vec<u8> = Vec::new();

    buf = [&buf[..], &g.to_bytes()[..]].concat();

    let mut hash = HASH256::new();
    hash.process_array(&buf);

    let h = hash.hash();
    
    buf = Vec::new();
    buf = [&buf[..], &h].concat();

    let nbits = G::get_order().nbytes() * 8;

    if nbits > buf.len() * 4 {
        let mut g: [u8; 32];
        for i in 1..(((nbits - buf.len() * 4) / buf.len() * 8) as f64).ceil() as isize {
            g = h.clone();
            hash.process_array(&[&g[..], &(i.to_ne_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    let mut res = G::BigInt::from_bytes(&buf);
    res.rmod(&G::BigInt::new_int(2));

    let bit = res.to_bytes()[res.nbytes() - 1];

    bit
}
