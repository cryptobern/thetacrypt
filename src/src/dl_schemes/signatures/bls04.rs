#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]

use mcore::{hash256::HASH256, rand::RAND};

use crate::{dl_schemes::{DlDomain, DlShare, common::interpolate, dl_groups::{dl_group::DlGroup, pairing::PairingEngine}, keygen::{DlKeyGenerator, DlPrivateKey, DlScheme}}, interface::{PrivateKey, PublicKey, Share, ThresholdSignature}, unwrap_keys, rand::RNG};
use crate::bigint::*;

pub struct Bls04ThresholdSignature<PE: PairingEngine> {
    g: PE
}

pub struct Bls04SignatureShare<PE: PairingEngine> {
    id:usize,
    label:Vec<u8>,
    data:PE::G2
}

pub struct Bls04SignedMessage<PE: PairingEngine> {
    msg: Vec<u8>,
    sig: PE::G2
}

#[derive(Clone)]
pub struct Bls04PublicKey<PE: PairingEngine> {
    y: PE,
    verificationKey:Vec<PE>
}  

#[derive(Clone)]
pub struct Bls04PrivateKey<PE: PairingEngine> {
    id: usize,
    xi: BigImpl,
    pubkey: Bls04PublicKey<PE>
}

impl<PE: PairingEngine> PublicKey for Bls04PublicKey<PE> {}

impl<PE: PairingEngine> PrivateKey for Bls04PrivateKey<PE> {
    type TPubKey = Bls04PublicKey<PE>;

    fn get_id(&self) -> usize {
        self.id
    }

    fn get_public_key(&self) -> Self::TPubKey {
        self.pubkey.clone()
    }
}

impl<PE:PairingEngine> Bls04PrivateKey<PE> {
    pub fn new(id: usize, xi: &BigImpl, pubkey: &Bls04PublicKey<PE>) -> Self {
        Self {id, xi:xi.clone(), pubkey:pubkey.clone()}
    }
}

impl<PE:PairingEngine> Bls04PublicKey<PE> {
    pub fn new(y: &PE, verificationKey: &Vec<PE>) -> Self {
        Self {y:y.clone(), verificationKey:verificationKey.clone()}
    }
}

impl<PE: PairingEngine> Share for Bls04SignatureShare<PE> {
    fn get_id(&self) -> usize {
        self.id
    }
}

impl<PE: PairingEngine> DlShare<PE::G2> for Bls04SignatureShare<PE> {
    fn get_data(&self) -> PE::G2 {
        self.data.clone()
    }
}

impl<PE: PairingEngine> Bls04SignedMessage<PE> {
    pub fn get_sig(&self) -> PE::G2 {
        self.sig.clone()
    }
}

pub struct Bls04Params {
}

impl<PE: PairingEngine> ThresholdSignature for Bls04ThresholdSignature<PE> {
    type TSig = Bls04SignedMessage<PE>;

    type TPubKey = Bls04PublicKey<PE>;

    type TPrivKey = Bls04PrivateKey<PE>;

    type TShare = Bls04SignatureShare<PE>;

    type TParams = Bls04Params;

    fn verify(sig: &Self::TSig, pk: &Self::TPubKey) -> bool {
        PE::ddh(&H::<PE::G2>(&sig.msg), &pk.y ,&sig.sig, &PE::new())
    }

    fn partial_sign(msg: &[u8], label: &[u8], sk: &Self::TPrivKey, params: Option<&mut Bls04Params>) -> Self::TShare {
        let mut data = H::<PE::G2>(&msg);
        data.pow(&sk.xi);

        Bls04SignatureShare{ id: sk.id, label:label.to_vec(), data:data }
    }

    fn verify_share(share: &Self::TShare, msg: &[u8], pk: &Self::TPubKey) -> bool {
        PE::ddh(&H::<PE::G2>(&msg), &pk.verificationKey[share.id - 1], &share.data, &PE::new())
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