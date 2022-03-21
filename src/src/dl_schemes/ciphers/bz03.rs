#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; 
use chacha20poly1305::aead::{Aead, NewAead};
use mcore::bls12381::big;
use mcore::hash256::*;
use rasn::{AsnType, Tag};

use crate::bigint::*;
use crate::dl_schemes::dl_groups::dl_group::DlGroup;
use crate::dl_schemes::dl_groups::pairing::PairingEngine;
use crate::dl_schemes::keygen::{DlKeyGenerator, DlPrivateKey, DlScheme};
use crate::dl_schemes::{DlDomain, DlShare, common::*};
use crate::rand::RNG;
use crate::{interface::*, unwrap_keys};

#[derive(Clone)]
pub struct Bz03PublicKey<PE: PairingEngine> {
    y: PE::G2,
    verificationKey: Vec<PE>
}

#[derive(Clone)]
pub struct Bz03PrivateKey<PE: PairingEngine> {
    id: usize,
    xi: BigImpl,
    pubkey: Bz03PublicKey<PE>
}

pub struct Bz03DecryptionShare<G: DlGroup> {
    id: usize,
    data: G
}

pub struct Bz03Ciphertext<PE: PairingEngine> {
    label: Vec<u8>,
    msg: Vec<u8>,
    c_k: Vec<u8>,
    u: PE::G2,
    hr: PE
}

pub struct Bz03ThresholdCipher<PE: PairingEngine> {
    g: PE
}

pub struct Bz03Params {
}


impl<PE: PairingEngine> PublicKey for Bz03PublicKey<PE> {
    fn encode(&self) -> Vec<u8> {
        todo!()
    }

    fn decode(bytes: Vec<u8>) -> Self {
        todo!()
    }
}

impl<PE:PairingEngine> PrivateKey for Bz03PrivateKey<PE> {
    type TPubKey = Bz03PublicKey<PE>;
    fn get_public_key(&self) -> Bz03PublicKey<PE>{
        self.pubkey.clone()
    }

    fn get_id(&self) -> usize {
        self.id as usize
    }

    fn encode(&self) -> Vec<u8> {
        todo!()
    }

    fn decode(bytes: Vec<u8>) -> Self {
        todo!()
    }
}

impl<PE:PairingEngine> Bz03PrivateKey<PE> {
    pub fn new(id: usize, xi: &BigImpl, pubkey: &Bz03PublicKey<PE>) -> Self {
        Self {id, xi:xi.clone(), pubkey:pubkey.clone()}
    }
}

impl<PE:PairingEngine> Bz03PublicKey<PE> {
    pub fn new(y: &PE::G2, verificationKey: &Vec<PE>) -> Self {
        Self {y:y.clone(), verificationKey:verificationKey.clone()}
    }
}

impl<G: DlGroup> Share for Bz03DecryptionShare<G> {
    fn get_id(&self) -> usize { self.id.clone() }

    fn encode(&self) -> Vec<u8> {
        todo!()
    }

    fn decode(bytes: Vec<u8>) -> Self {
        todo!()
    }
}

impl<G: DlGroup> DlShare<G> for Bz03DecryptionShare<G> {
    fn get_data(&self) -> G {
        self.data.clone()
    }
}

impl<PE: PairingEngine> Ciphertext for Bz03Ciphertext<PE> {
    fn get_msg(&self) -> Vec<u8> { self.msg.clone() }
    fn get_label(&self) -> Vec<u8> { self.label.clone() }

    fn encode(&self) -> Vec<u8> {
        todo!()
    }

    fn decode(bytes: Vec<u8>) -> Self {
        todo!()
    }
}

impl<PE: PairingEngine> ThresholdCipher for Bz03ThresholdCipher<PE> {
    type CT = Bz03Ciphertext<PE>;

    type TPubKey = Bz03PublicKey<PE>;

    type TPrivKey = Bz03PrivateKey<PE>;

    type TShare = Bz03DecryptionShare<PE::G2>;

    type TParams = Bz03Params;

    fn encrypt(msg: &[u8], label: &[u8], pk: &Self::TPubKey, rng: &mut RNG) -> Self::CT {
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

        let c = Bz03Ciphertext{label:label.to_vec(), msg:encryption, c_k:c_k.to_vec(), u:u, hr:hr};
        c
    }

    fn verify_ciphertext(ct: &Self::CT, _pk: &Self::TPubKey) -> bool {
        let h = H::<PE::G2, PE>(&ct.u, &ct.msg);

        PE::ddh(&ct.u, &h, &PE::G2::new(), &ct.hr)
    }

    fn verify_share(share: &Self::TShare, ct: &Self::CT, pk: &Self::TPubKey) -> bool {
        PE::ddh(&share.data, &PE::new(), &ct.u, &pk.verificationKey[(&share.id - 1)])
    }

    fn partial_decrypt(ct: &Self::CT, sk: &Self::TPrivKey, _params: Option<&mut Bz03Params>) -> Self::TShare {
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

impl<PE: PairingEngine> AsnType for Bz03PrivateKey<PE> {
    const TAG: Tag = Tag::SEQUENCE;
}

