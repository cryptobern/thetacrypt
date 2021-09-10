#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; 
use chacha20poly1305::aead::{Aead, NewAead};
use mcore::rand::RAND;
use mcore::bls12381::big;
use mcore::hash256::*;

use crate::bigint::BigInt;
use crate::dl_schemes::dl_groups::BigImpl;
use crate::dl_schemes::dl_groups::dl_group::DlGroup;
use crate::dl_schemes::dl_groups::pairing::PairingEngine;
use crate::dl_schemes::keygen::{DlKeyGenerator, DlPrivateKey, DlScheme};
use crate::dl_schemes::{DlDomain, DlShare, common::*};
use crate::{interface::*, unwrap_keys};

pub struct BZ03_PublicKey<PE: PairingEngine> {
    y: PE::G2,
    verificationKey: Vec<PE>
}

pub struct BZ03_PrivateKey<PE: PairingEngine> {
    id: usize,
    xi: BigImpl,
    pubkey: BZ03_PublicKey<PE>
}

pub struct BZ03_DecryptionShare<G: DlGroup> {
    id: usize,
    data: G
}

pub struct BZ03_Ciphertext<PE: PairingEngine> {
    label: Vec<u8>,
    msg: Vec<u8>,
    c_k: Vec<u8>,
    u: PE::G2,
    hr: PE
}

pub struct BZ03_ThresholdCipher<PE: PairingEngine> {
    g: PE
}


impl<PE: PairingEngine> Clone for BZ03_PublicKey<PE> {
    fn clone(&self) -> Self {
        Self {y:self.y.clone(), verificationKey:self.verificationKey.clone()}
    }
}

impl<PE: PairingEngine> Clone for BZ03_PrivateKey<PE> {
    fn clone(&self) -> Self {
        Self { id: self.id.clone(), xi: self.xi.clone(), pubkey: self.pubkey.clone() }
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

impl<PE:PairingEngine> BZ03_PrivateKey<PE> {
    pub fn new(id: usize, xi: &BigImpl, pubkey: &BZ03_PublicKey<PE>) -> Self {
        Self {id, xi:xi.clone(), pubkey:pubkey.clone()}
    }
}

impl<PE:PairingEngine> BZ03_PublicKey<PE> {
    pub fn new(y: &PE::G2, verificationKey: &Vec<PE>) -> Self {
        Self {y:y.clone(), verificationKey:verificationKey.clone()}
    }
}

impl<G: DlGroup> Share for BZ03_DecryptionShare<G> {
    fn get_id(&self) -> usize { self.id.clone() }
}

impl<G: DlGroup> DlShare<G> for BZ03_DecryptionShare<G> {
    fn get_data(&self) -> G {
        self.data.clone()
    }
}

impl<PE: PairingEngine> Ciphertext for BZ03_Ciphertext<PE> {
    fn get_msg(&self) -> Vec<u8> { self.msg.clone() }
    fn get_label(&self) -> Vec<u8> { self.label.clone() }
}

impl<PE: PairingEngine> ThresholdCipher for BZ03_ThresholdCipher<PE> {
    type CT = BZ03_Ciphertext<PE>;

    type PK = BZ03_PublicKey<PE>;

    type SK = BZ03_PrivateKey<PE>;

    type SH = BZ03_DecryptionShare<PE::G2>;

    fn encrypt(msg: &[u8], label: &[u8], pk: &Self::PK, rng: &mut impl RAND) -> Self::CT {
        let r = PE::BigInt::new_rand(&PE::G2::get_order(), rng);
        let mut u = PE::G2::new();
        u.pow(&r);

        let mut rY = pk.y.clone();
        rY.pow(&r);

        let k = gen_symm_key(rng);
        let key = Key::from_slice(&k);
        let cipher = ChaCha20Poly1305::new(key);
        let encryption: Vec<u8> = cipher
            .encrypt(Nonce::from_slice(&rY.to_bytes()[0..12]),  msg)
            .expect("encryption failure");
            
        let c_k = xor(G(&rY), (k).to_vec());

        let mut hr = H::<PE::G2, PE>(&u, &encryption);
        hr.pow(&r);

        let c = BZ03_Ciphertext{label:label.to_vec(), msg:encryption, c_k:c_k.to_vec(), u:u, hr:hr};
        c
    }

    fn verify_ciphertext(ct: &Self::CT, _pk: &Self::PK) -> bool {
        let h = H::<PE::G2, PE>(&ct.u, &ct.msg);

        PE::ddh(&ct.u, &h, &PE::G2::new(), &ct.hr)
    }

    fn verify_share(share: &Self::SH, ct: &Self::CT, pk: &Self::PK) -> bool {
        PE::ddh(&share.data, &PE::new(), &ct.u, &pk.verificationKey[(&share.id - 1)])
    }

    fn partial_decrypt(ct: &Self::CT, sk: &Self::SK, _rng: &mut impl RAND) -> Self::SH {
        let mut u = ct.u.clone();
        u.pow(&sk.xi);

        BZ03_DecryptionShare {id:sk.id, data: u}
    }

    fn assemble(shares: &Vec<Self::SH>, ct: &Self::CT) -> Vec<u8> {
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

impl<D:DlDomain> BZ03_ThresholdCipher<D> {
    pub fn generate_keys(k: usize, n: usize, domain: D, rng: &mut impl RAND) -> Vec<BZ03_PrivateKey<D>> {
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