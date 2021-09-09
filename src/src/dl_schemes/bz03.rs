#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use mcore::rand::RAND;
use mcore::bls12381::ecp::ECP;
use mcore::bls12381::big;
use mcore::bls12381::ecp2::ECP2;
use mcore::bls12381::big::BIG;
use mcore::bls12381::rom;
use mcore::bls12381::pair;
use mcore::hmac::*;
use mcore::aes::*;
use mcore::hash256::*;

use crate::bigint::BigInt;
use crate::dl_schemes::dl_groups::dl_group::DlGroup;
use crate::dl_schemes::dl_groups::pairing::PairingEngine;
use crate::dl_schemes::common::*;
use crate::interface::*;

use super::DlShare;
use super::dl_groups::BigImpl;

pub struct BZ03_PublicKey<PE: PairingEngine> {
    pub y: PE::G2,
    pub verificationKey: Vec<PE>
}

pub struct BZ03_PrivateKey<PE: PairingEngine> {
    pub id: usize,
    pub xi: BigImpl,
    pub pubkey: BZ03_PublicKey<PE>
}

impl<PE: PairingEngine> Clone for BZ03_PublicKey<PE> {
    fn clone(&self) -> Self {
        Self {y:self.y.clone(), verificationKey:self.verificationKey.clone()}
    }
}

impl<PE: PairingEngine> PublicKey for BZ03_PublicKey<PE> {}

impl<PE:PairingEngine> PrivateKey for BZ03_PrivateKey<PE> {
    type PK = BZ03_PublicKey<PE>;
    fn get_public_key(&self) -> BZ03_PublicKey<PE>{
        self.pubkey.clone()
    }

    fn get_id(&self) -> usize {
        self.id as usize
    }
}

pub struct BZ03_DecryptionShare<G: DlGroup> {
    id: usize,
    data: G
}

impl<G: DlGroup> Share for BZ03_DecryptionShare<G> {
    fn get_id(&self) -> usize { self.id.clone() }
}

impl<G: DlGroup> DlShare<G> for BZ03_DecryptionShare<G> {
    fn get_data(&self) -> G {
        self.data.clone()
    }
}

pub struct BZ03_Ciphertext<PE: PairingEngine> {
    label: Vec<u8>,
    msg: Vec<u8>,
    c_k: Vec<u8>,
    u: PE::G2,
    hr: PE
}

impl<PE: PairingEngine> Ciphertext for BZ03_Ciphertext<PE> {
    fn get_msg(&self) -> Vec<u8> { self.msg.clone() }
    fn get_label(&self) -> Vec<u8> { self.label.clone() }
}


pub struct BZ03_ThresholdCipher<PE: PairingEngine> {
    g: PE
}

impl<PE: PairingEngine> ThresholdCipher for BZ03_ThresholdCipher<PE> {
    type CT = BZ03_Ciphertext<PE>;

    type PK = BZ03_PublicKey<PE>;

    type SK = BZ03_PrivateKey<PE>;

    type SH = BZ03_DecryptionShare<PE::G2>;

    fn encrypt(msg: &[u8], label: &[u8], pk: &Self::PK, rng: &mut impl RAND) -> Self::CT {
        let k = gen_symm_key(rng);

        let r = PE::BigInt::new_rand(&PE::G2::get_order(), rng);
        let mut u = PE::G2::new();
        u.pow(&r);

        let mut rY = pk.y.clone();
        rY.pow(&r);

        let c_k = xor(G(&rY), (k).to_vec());

        let mut encryption: Vec<u8> = vec![0; msg.len()];
        cbc_iv0_encrypt(&k, &msg, &mut encryption);

        let mut hr = H::<PE::G2, PE>(&u, &encryption);
        hr.pow(&r);

        let c = BZ03_Ciphertext{label:label.to_vec(), msg:encryption, c_k:c_k.to_vec(), u:u, hr:hr};
        c
    }

    fn verify_ciphertext(ct: &Self::CT, pk: &Self::PK) -> bool {
        let h = H::<PE::G2, PE>(&ct.u, &ct.msg);

        PE::ddh(&ct.u, &h, &PE::G2::new(), &ct.hr)
    }

    fn verify_share(share: &Self::SH, ct: &Self::CT, pk: &Self::PK) -> bool {
        PE::ddh(&share.data, &PE::new(), &ct.u, &pk.verificationKey[(&share.id - 1)])
    }

    fn partial_decrypt(ct: &Self::CT, sk: &Self::SK, rng: &mut impl RAND) -> Self::SH {
        let mut u = ct.u.clone();
        u.pow(&sk.xi);

        BZ03_DecryptionShare {id:sk.id, data: u}
    }

    fn assemble(shares: &Vec<Self::SH>, ct: &Self::CT) -> Vec<u8> {
        let rY = interpolate(shares);

        let key = xor(G(&rY), ct.c_k.clone());
        
        let mut msg: Vec<u8> = vec![0; 44];
        cbc_iv0_decrypt(&key, &ct.msg.clone(), &mut msg);

        msg
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