#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]


use mcore::rand::RAND;
use mcore::hash256::*;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; 
use chacha20poly1305::aead::{Aead, NewAead};

use crate::dl_schemes::common::gen_symm_key;
use crate::dl_schemes::common::interpolate;
use crate::dl_schemes::common::xor;
use crate::dl_schemes::dl_groups::dl_group::*;
use crate::dl_schemes::keygen::{DlKeyGenerator, DlPrivateKey, DlScheme};
use crate::{interface::*, unwrap_keys};
use crate::interface::PrivateKey;
use crate::interface::PublicKey;
use crate::interface::Share;
use crate::interface::ThresholdCipher;
use crate::bigint::*;

use crate::dl_schemes::{DlDomain, DlShare};

#[derive(Clone)]
pub struct SG02_PublicKey<G: DlGroup> {
    y: G,
    verificationKey: Vec<G>,
    g_bar: G
}

#[derive(Clone)]
pub struct SG02_PrivateKey<G: DlGroup> {
    id: usize,
    xi: BigImpl,
    pubkey: SG02_PublicKey<G>,
}

pub struct SG02_Ciphertext<G: DlGroup> {
    label: Vec<u8>,
    msg: Vec<u8>,
    u: G,
    u_bar: G,
    e: BigImpl,
    f: BigImpl,
    c_k: Vec<u8>,
}

pub struct SG02_DecryptionShare<G: DlGroup>  {
    id: usize,
    label: Vec<u8>,
    data: G,
    ei: BigImpl,
    fi: BigImpl,
}

impl<G: DlGroup> PublicKey for SG02_PublicKey<G> {}

impl<G: DlGroup> PrivateKey for SG02_PrivateKey<G> {
    type PK = SG02_PublicKey<G>;
    fn get_public_key(&self) -> SG02_PublicKey<G> {
        self.pubkey.clone()
    }

    fn get_id(&self) -> usize {
        self.id 
    }
}

impl<G: DlGroup> SG02_PrivateKey<G> {
    pub fn new(id: usize, xi: &BigImpl, pubkey: &SG02_PublicKey<G>) -> Self {
        Self {id, xi:xi.clone(), pubkey:pubkey.clone()}
    }
}

impl<G: DlGroup> SG02_PublicKey<G> {
    pub fn new(y: &G, verificationKey: &Vec<G>, g_bar:&G) -> Self {
        Self {y:y.clone(), verificationKey:verificationKey.clone(), g_bar:g_bar.clone()}
    }
}

impl<G: DlGroup> Ciphertext for SG02_Ciphertext<G> {
    fn get_msg(&self) -> Vec<u8> {
        self.msg.clone()
    }

    fn get_label(&self) -> Vec<u8> {
        self.label.clone()
    }
}

impl<G: DlGroup> Share for SG02_DecryptionShare<G> {
    fn get_id(&self) -> usize {
        self.id as usize
    }
}

impl<G: DlGroup> DlShare<G> for SG02_DecryptionShare<G> {
    fn get_data(&self) -> G {
        self.data.clone()
    }
}

pub struct SG02_ThresholdCipher<G: DlGroup> {
    g: G
}

impl<G:DlGroup> ThresholdCipher for SG02_ThresholdCipher<G> {
    type PK = SG02_PublicKey<G>;
    type SK = SG02_PrivateKey<G>;
    type CT = SG02_Ciphertext<G>;
    type SH = SG02_DecryptionShare<G>;

    fn encrypt(msg: &[u8], label: &[u8], pk: &SG02_PublicKey<G>, rng: &mut impl RAND) -> Self::CT {
        let r = G::BigInt::new_rand(&G::get_order(), rng);
        let mut u = G::new();
        u.pow(&r);

        let mut rY = pk.y.clone();
        rY.pow(&r);

        let k = gen_symm_key(rng);
        let key = Key::from_slice(&k);
        let cipher = ChaCha20Poly1305::new(key);
        let encryption: Vec<u8> = cipher
            .encrypt(Nonce::from_slice(&rY.to_bytes()[0..12]),  msg)
            .expect("encryption failure");
        
        let c_k = xor(H(&rY), (k).to_vec());
      
        let s = G::BigInt::new_rand(&G::get_order(), rng);
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

        let c = SG02_Ciphertext{label:label.to_vec(), msg:encryption, c_k:c_k.to_vec(), u:u, u_bar:u_bar, e:e, f:f};
        c
    }

    fn verify_ciphertext(ct: &Self::CT, pk: &Self::PK) -> bool {
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

    fn verify_share(share: &Self::SH, ct: &Self::CT, pk: &Self::PK) -> bool {
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

    fn partial_decrypt(ct: &Self::CT, sk: &Self::SK, rng: &mut impl RAND) -> Self::SH {
        let mut data = ct.u.clone();
        data.pow(&sk.xi);

        let si = G::BigInt::new_rand(&G::get_order(), rng);

        let mut ui_bar = ct.u.clone();
        ui_bar.pow(&si);

        let mut hi_bar = G::new();
        hi_bar.pow(&si);

        let ei = H2(&data, &ui_bar, &hi_bar);
        let mut fi = si.clone();
        fi.add(&BigImpl::rmul(&sk.xi, &ei, &G::get_order()));
        fi.rmod(&G::get_order());

        SG02_DecryptionShare { id:sk.id.clone(), data:data, label:ct.label.clone(), ei:ei, fi:fi}
    }

    fn assemble(shares: &Vec<Self::SH>, ct: &Self::CT) -> Vec<u8> {
        let rY = interpolate(shares);

        let k = xor(H(&rY), ct.c_k.clone());
        let key = Key::from_slice(&k);
        let cipher = ChaCha20Poly1305::new(key);
        let msg = cipher
            .decrypt(Nonce::from_slice(&rY.to_bytes()[0..12]), ct.msg.as_ref())
            .expect("decryption failure");
        
        msg
    }
}

impl<D:DlDomain> SG02_ThresholdCipher<D> {
    pub fn generate_keys(k: usize, n: usize, domain: D, rng: &mut impl RAND) -> Vec<SG02_PrivateKey<D>> {
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