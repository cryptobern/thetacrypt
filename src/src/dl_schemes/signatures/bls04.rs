use std::str::ParseBoolError;

use mcore::hash256::HASH256;

use crate::{dl_schemes::{DlShare, common::interpolate, dl_groups::{BigImpl, dl_group::DlGroup, pairing::PairingEngine}}, interface::{PrivateKey, PublicKey, Share, ThresholdSignature}};
use crate::bigint::*;

pub struct BLS04_ThresholdSignature<PE: PairingEngine> {
    g: PE
}

pub struct BLS04_SignatureShare<PE: PairingEngine> {
    pub id:usize,
    pub label:Vec<u8>,
    pub data:PE::G2
}

pub struct BLS04_SignedMessage<PE: PairingEngine> {
    pub msg: Vec<u8>,
    pub sig: PE::G2
}

pub struct BLS04_PublicKey<PE: PairingEngine> {
    pub y: PE,
    pub verificationKey:Vec<PE>
}  

pub struct BLS04_PrivateKey<PE: PairingEngine> {
    pub id: usize,
    pub xi: BigImpl,
    pub pubkey: BLS04_PublicKey<PE>
}

impl<PE: PairingEngine> PublicKey for BLS04_PublicKey<PE> {}

impl<PE: PairingEngine> PrivateKey for BLS04_PrivateKey<PE> {
    type PK = BLS04_PublicKey<PE>;

    fn get_id(&self) -> usize {
        self.id
    }

    fn get_public_key(&self) -> Self::PK {
        self.pubkey.clone()
    }
}

impl<PE: PairingEngine> Clone for BLS04_PublicKey<PE> {
    fn clone(&self) -> Self {
        Self { y: self.y.clone(), verificationKey: self.verificationKey.clone() }
    }
}

impl<PE: PairingEngine> Share for BLS04_SignatureShare<PE> {
    fn get_id(&self) -> usize {
        self.id
    }
}

impl<PE: PairingEngine> DlShare<PE::G2> for BLS04_SignatureShare<PE> {
    fn get_data(&self) -> PE::G2 {
        self.data.clone()
    }
}

impl<PE: PairingEngine> ThresholdSignature for BLS04_ThresholdSignature<PE> {
    type SM = BLS04_SignedMessage<PE>;

    type PK = BLS04_PublicKey<PE>;

    type SK = BLS04_PrivateKey<PE>;

    type SH = BLS04_SignatureShare<PE>;

    fn verify(sig: &Self::SM, pk: &Self::PK) -> bool {
        PE::ddh(&H::<PE::G2>(&sig.msg), &pk.y ,&sig.sig, &PE::new())
    }

    fn partial_sign(msg: &[u8], sk: &Self::SK) -> Self::SH {
        let mut data = H::<PE::G2>(&msg);
        data.pow(&sk.xi);

        BLS04_SignatureShare{ id: sk.id, label:b"".to_vec(), data:data }
    }

    fn verify_share(share: &Self::SH, msg: &[u8], pk: &Self::PK) -> bool {
        PE::ddh(&H::<PE::G2>(&msg), &pk.verificationKey[share.id - 1], &share.data, &PE::new())
    }

    fn assemble(shares: &Vec<Self::SH>, msg: &[u8], pk: &Self::PK) -> Self::SM {
        let sig = interpolate(&shares);
        BLS04_SignedMessage{sig:sig, msg:msg.to_vec() } 
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