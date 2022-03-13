#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use mcore::{hash256::HASH256, rand::RAND};

use crate::dl_schemes::common::interpolate;
use crate::dl_schemes::keygen::{DlKeyGenerator, DlPrivateKey, DlScheme};
use crate::rand::RNG;
use crate::{bigint::*, unwrap_keys};
use crate::dl_schemes::{DlDomain, DlShare};
use crate::{
    dl_schemes::dl_groups::{dl_group::DlGroup},
    interface::{PrivateKey, PublicKey, Share, ThresholdCoin},
};

pub struct Cks05ThresholdCoin<G: DlGroup> {
    g: G,
}

#[derive(Clone)]
pub struct Cks05PublicKey<G: DlGroup> {
    y: G,
    verificationKey: Vec<G>
}

#[derive(Clone)]
pub struct Cks05PrivateKey<G: DlGroup> {
    id: usize,
    xi: BigImpl,
    pubkey: Cks05PublicKey<G>,
}

pub struct Cks05CoinShare<G: DlGroup> {
    id: usize,
    data: G,
    c: BigImpl,
    z: BigImpl,
}

impl<G: DlGroup> PublicKey for Cks05PublicKey<G> {}

impl<G: DlGroup> PrivateKey for Cks05PrivateKey<G> {
    type TPubKey = Cks05PublicKey<G>;

    fn get_id(&self) -> usize {
        self.id
    }

    fn get_public_key(&self) -> Self::TPubKey {
        self.pubkey.clone()
    }
}

impl<G: DlGroup> Cks05PublicKey<G> {
    pub fn new(y: &G, verificationKey: &Vec<G>) -> Self {
        Self {
            y: y.clone(),
            verificationKey: verificationKey.clone()
        }
    }
}

impl<G: DlGroup> Cks05PrivateKey<G> {
    pub fn new(id: usize, xi: &BigImpl, pubkey: &Cks05PublicKey<G>) -> Self {
        Self {
            id,
            xi: xi.clone(),
            pubkey: pubkey.clone(),
        }
    }
}

impl<G: DlGroup> Share for Cks05CoinShare<G> {
    fn get_id(&self) -> usize {
        self.id
    }
}

impl<G: DlGroup> DlShare<G> for Cks05CoinShare<G>{
    fn get_data(&self) -> G {
        self.data.clone()
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
            &sk.pubkey.verificationKey[sk.id - 1],
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

        let mut rhs = pk.verificationKey[share.id -1].clone();
        rhs.pow(&share.c);

        h.div(&rhs);

        let mut h_bar = c_bar.clone();
        h_bar.pow(&share.z);

        let mut rhs = share.data.clone();
        rhs.pow(&share.c);

        h_bar.div(&rhs);

        let c = H1(
            &G::new(),
            &pk.verificationKey[share.id - 1],
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
