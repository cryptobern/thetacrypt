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

use crate::dl_schemes::common::gen_symm_key;
use crate::dl_schemes::common::xor;
use crate::dl_schemes::dl_groups::dl_group::*;
use crate::interface::Ciphertext;
use crate::interface::PrivateKey;
use crate::interface::PublicKey;
use crate::interface::Share;
use crate::interface::ThresholdCipher;
use crate::bigint::BigInt;

use super::dl_groups::BigImpl;

pub struct SG02_PublicKey<G: DlGroup> {
    pub y: G,
    pub verificationKey: Vec<G>,
    pub g_bar: G
}

impl<G: DlGroup> Clone for SG02_PublicKey<G> {
    fn clone(&self) -> SG02_PublicKey<G> {
        return SG02_PublicKey {y:self.y.clone(), verificationKey:self.verificationKey.clone(), g_bar:self.g_bar.clone() };
    }
}
pub struct SG02_PrivateKey<G: DlGroup> {
    pub id: u8,
    pub xi: BigImpl,
    pub pubkey: SG02_PublicKey<G>,
}

impl<G: DlGroup> PublicKey for SG02_PublicKey<G> {}

impl<G: DlGroup> PrivateKey for SG02_PrivateKey<G> {
    type PK = SG02_PublicKey<G>;
    fn get_public_key(&self) -> SG02_PublicKey<G> {
        self.pubkey.clone()
    }
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
    id: u8,
    label: Vec<u8>,
    data: G,
    ei: BigImpl,
    fi: BigImpl,
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
    fn get_id(&self) -> u8 {
        self.id.clone()
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
        let k = gen_symm_key(rng);

        let r = G::BigInt::new_rand(&G::get_order(), rng);
        let mut u = G::new();
        u.pow(&r);

        let mut rY = pk.y.clone();
        rY.pow(&r);

        let c_k = xor(H(&rY), (k).to_vec());

        let mut encryption: Vec<u8> = vec![0; msg.len()];
        cbc_iv0_encrypt(&k, &msg, &mut encryption);

        let s = G::BigInt::new_rand(&G::get_order(), rng);
        let mut w = G::new();
        w.pow(&s);

        let mut w_bar = pk.g_bar.clone();
        w_bar.pow(&s);

        let mut u_bar = pk.g_bar.clone();
        u_bar.pow(&r);

        let e = H1(&c_k, &label, &u, &w, &u_bar, &w_bar);

        let mut f = BigImpl::rmul(&e, &r, &G::get_order());
        f.add(&s);

        let c = SG02_Ciphertext{label:label.to_vec(), msg:encryption, c_k:c_k.to_vec(), u:u, u_bar:u_bar, e:e, f:f};
        c
    }

    fn verify_ciphertext(ct: &Self::CT, pk: &Self::PK) -> bool {
        true
    }

    fn verify_share(share: &Self::SH, ct: &Self::CT, pk: &Self::PK) -> bool {
        true
    }

    fn partial_decrypt(ct: &Self::CT, sk: &Self::SK, rng: &mut impl RAND) -> Self::SH {
        let mut data = ct.u.clone();
        data.pow(&sk.xi);

        let si = G::BigInt::new_rand(&G::get_order(), rng);

        let mut ui_bar = ct.u.clone();
        ui_bar.pow(&si);

        let mut hi_bar = G::new();
        ui_bar.pow(&si);

        let ei = H2(&data, &ui_bar, &hi_bar);
        let mut fi = BigImpl::rmul(&sk.xi, &ei, &G::get_order());
        fi.add(&si);

        SG02_DecryptionShare { id:sk.id.clone(), data:data, label:ct.label.clone(), ei:ei, fi:fi}
    }

    fn assemble(shares: &Vec<Self::SH>, ct: &Self::CT) -> Vec<u8> {
        vec![0;100]
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
    let mut bytes:Vec<u8>= vec![0;180];
    let mut buf:Vec<u8> = Vec::new();
    let q = BIG::new_ints(&rom::CURVE_ORDER);

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
    
    if q.nbits() > buf.len()*4 {
        let mut g:[u8;32];
        for i in 1..(((q.nbits() - buf.len()*4)/buf.len()*8) as f64).ceil() as isize {
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
    let mut bytes:Vec<u8>= vec![0;180];
    let mut buf:Vec<u8> = Vec::new();
    let q = BIG::new_ints(&rom::CURVE_ORDER);

    buf = [&buf[..], &g1.to_bytes()[..]].concat();
    buf = [&buf[..], &g2.to_bytes()[..]].concat();
    buf = [&buf[..], &g3.to_bytes()[..]].concat();

    let mut hash = HASH256::new();
    hash.process_array(&buf);
    let h = hash.hash();

    buf = Vec::new();
    buf = [&buf[..], &h].concat();
    
    if q.nbits() > buf.len()*4 {
        let mut g:[u8;32];
        for i in 1..(((q.nbits() - buf.len()*4)/buf.len()*8) as f64).ceil() as isize {
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


/*


impl SG02_ThresholdCipher {

    pub fn encrypt(&self, msg:Vec<u8>, label:&Vec<u8>, rng: &mut impl RAND) -> SG02_Ciphertext {
        let k = gen_symm_key(rng);

        let q = BIG::new_ints(&rom::CURVE_ORDER);
        let r = BIG::randomnum(&q, rng);
        let mut u = ECP::generator();
        u = u.mul(&r);

        let mut rY = self.y.clone();
        rY = rY.mul(&r);

        let c_k = xor(H(&rY), (k).to_vec());

        let mut encryption: Vec<u8> = vec![0; msg.len()];
        cbc_iv0_encrypt(&k, &msg, &mut encryption);

        let s = BIG::randomnum(&q, rng);
        let mut w = ECP::generator();
        w = w.mul(&s);

        let mut w_bar = self.g_hat.clone();
        w_bar = w_bar.mul(&s);

        let mut u_bar = self.g_hat.clone();
        u_bar = u_bar.mul(&r);

        let e = H1(&c_k, &label, &u, &w, &u_bar, &w_bar);

        let mut f = BIG::mul(&e, &r).dmod(&q);
        f.add(&s);

        println!("encrypt zkp:");
        println!("{}", w.tostring());
        println!("{}", w_bar.tostring());

        let c = SG02_Ciphertext{label:label.clone(), msg:encryption, c_k:c_k.to_vec(), u:u, u_bar:u_bar, e:e, f:f};
        c
    }

    pub fn assemble(&self, shares: &Vec<SG02_DecryptionShare>, ct: &SG02_Ciphertext) -> Vec<u8> {
        let rY = interpol_exp(shares);

        let key = xor(H(&rY), ct.c_k.clone());
        
        let mut msg: Vec<u8> = vec![0; 44];
        cbc_iv0_decrypt(&key, &ct.msg.clone(), &mut msg);
        
        msg
    }


    pub fn verify_share(&self, share: &SG02_DecryptionShare, ct: &SG02_Ciphertext) -> bool {
        let mut ui_bar = ct.u.mul(&share.fi.clone());
        let rhs = share.data.mul(&share.ei);
        ui_bar.sub(&rhs);

        let mut hi_bar = ECP::generator().mul(&share.fi.clone());
        let rhs = self.verificationKey[share.get_id() as usize].mul(&share.ei);
        hi_bar.sub(&rhs);

        let e2 = H2(&share.data, &ui_bar, &hi_bar);

        BIG::comp(&ct.e, &e2) == 0
    }

    pub fn verify_ciphertext(&self, ct: &SG02_Ciphertext) -> bool {
        let mut w = ECP::generator().mul(&ct.f);
        let rhs = ct.u.mul(&ct.e);
        w.sub(&rhs);

        let mut w_bar = self.g_hat.mul(&ct.f);
        let rhs = ct.u_bar.mul(&ct.e);
        w_bar.sub(&rhs);

        println!("verify ciphertext:");
        println!("{}", w.tostring());
        println!("{}", w_bar.tostring());

        BIG::comp(&ct.e, &H1(&ct.c_k, &ct.label, &ct.u, &w, &ct.u_bar, &w_bar)) == 0
    }

}




impl SG02_PrivateKey {
    pub fn partial_decrypt(&self, ct: &SG02_Ciphertext, rng: &mut impl RAND) -> SG02_DecryptionShare {
        let mut data = ct.u.clone();
        data = data.mul(&self.xi);

        let q = BIG::new_ints(&rom::CURVE_ORDER);

        let si = BIG::randomnum(&q, rng);

        let ui_bar = ct.u.mul(&si);
        let hi_bar = self.pubkey.group.g.mul(&si);

        let ei = H2(&data, &ui_bar, &hi_bar);
        let mut fi = BIG::mul(&self.xi, &ei).dmod(&q);
        fi.add(&si);

        SG02_DecryptionShare { id:self.id.clone(), data:data, label:ct.label.clone(), ei:ei, fi:fi}
    }
}

pub fn interpol_exp(shares: &Vec<SG02_DecryptionShare>) -> ECP { 
    let ids:Vec<u8> = (0..shares.len()).map(|x| shares[x].get_id()).collect();
    let mut rY = ECP::new();

    for i in 0..shares.len() {
        let l = lagrange_coeff(&ids, shares[i].get_id() as isize);
        let mut ui = shares[i].get_data().clone();
        ui = ui.mul(&l);
        if i == 0 {
            rY = ui;
        } else {
            rY.add(&ui);
        }
    }

    rY
} */