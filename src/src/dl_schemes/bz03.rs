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

use super::dl_groups::BigImpl;

pub struct BZ03_PublicKey<PE: PairingEngine> {
    pub y: PE::G2,
    pub verificationKey: Vec<PE>
}

pub struct BZ03_PrivateKey<PE: PairingEngine> {
    pub id: u8,
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
}


/*



pub struct BZ03_DecryptionShare<G: DlGroup> {
    id: u8,
    data: G
}

impl<G: DlGroup> Share<G> for BZ03_DecryptionShare<G> {
    fn get_id(&self) -> u8 { self.id.clone() }
    fn get_data(&self) -> G { self.data.clone() }
}

pub struct BZ03_Ciphertext<PE: PairingEngine> {
    label: Vec<u8>,
    msg: Vec<u8>,
    c_k: Vec<u8>,
    u: PE::G2,
    hr: PE::G1
}

impl<PE: PairingEngine> Ciphertext for BZ03_Ciphertext<PE> {
    fn get_msg(&self) -> Vec<u8> { self.msg.clone() }
    fn get_label(&self) -> Vec<u8> { self.label.clone() }
}

pub fn bz03_gen_keys<PK: PublicKey, SK: PrivateKey, PE:PairingEngine> (k: u8, n:u8, rng: &mut impl RAND) -> (PK, Vec<SK>) {
    let x = BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng);
    let mut y = ECP2::generator();
    y = y.mul(&x);

    let s = BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng);

    let (shares, h) = shamir_share(&x, &k, &n, rng);
    let pk = BZ03_PublicKey {y:y.clone(), verificationKey:h.clone() };
    let mut sk = Vec::new();
    
    for j in 1..n+1 {
        sk.push(BZ03_PrivateKey::<PE> {id:j, xi:shares[(j -1) as usize], pubkey:pk.clone()});
    }

    (pk, sk)
}  
*/
/*

impl<PE: PairingEngine> BZ03_PrivateKey<PE> {
    pub fn partial_decrypt(&self, ct: &BZ03_Ciphertext<PE>) -> BZ03_DecryptionShare<PE::G2> {
        let mut u = ct.u.clone();
        u.mul(&self.xi);

        BZ03_DecryptionShare {id:self.id.clone(), data: u.clone()}
    }
}

fn H(g: &ECP2, m: &Vec<u8>) -> ECP {
    let mut bytes: Vec<u8> = vec![0;256];
    g.tobytes(&mut bytes, false);

    let mut h = HASH256::new();
    h.process_array(&[&bytes[..], &m[..]].concat());

    let h = [&vec![0;big::MODBYTES - 32][..], &h.hash()[..]].concat();

    let mut s = BIG::frombytes(&h);
    s.rmod(&BIG::new_ints(&rom::CURVE_ORDER));

    ECP::generator().mul(&s)
}

impl <PE:PairingEngine> BZ03_PublicKey<PE> {
    pub fn encrypt(&self, msg:Vec<u8>, label:&Vec<u8>, rng: &mut impl RAND) -> BZ03_Ciphertext<PE> {
        let k = gen_symm_key(rng);

        let q = BIG::new_ints(&rom::CURVE_ORDER);
        let r = BIG::randomnum(&q, rng);
        let mut u = ECP2::generator();
        u = u.mul(&r);

        let mut rY = self.y.clone();
        rY = rY.mul(&r);

        let c_k = xor(G(&rY), (k).to_vec());

        let mut encryption: Vec<u8> = vec![0; msg.len()];
        cbc_iv0_encrypt(&k, &msg, &mut encryption);

        let hr = H(&u, &encryption).mul(&r);

        let c = BZ03_Ciphertext{label:label.clone(), msg:encryption, c_k:c_k.to_vec(), u:u, hr:hr};
        c
    }


    pub fn assemble(&self, shares:&Vec<BZ03_DecryptionShare<PE::G2>>, ct:&BZ03_Ciphertext<PE>) -> Vec<u8> {
        let rY = interpolate(shares);

        let key = xor(G(&rY), ct.c_k.clone());
        
        let mut msg: Vec<u8> = vec![0; 44];
        cbc_iv0_decrypt(&key, &ct.msg.clone(), &mut msg);

        msg
    }

    pub fn verify_ciphertext(&self, ct: &BZ03_Ciphertext<PE>) -> bool {
        let h = H(&ct.u, &ct.msg);

        let mut lhs =  pair::ate(&ct.u, &h);
        lhs = pair::fexp(&lhs);

        let mut rhs = pair::ate(&ECP2::generator(), &ct.hr);
        rhs = pair::fexp(&rhs);
        
        lhs.equals(&rhs)
    }

    pub fn verify_share(&self, share: &BZ03_DecryptionShare<PE::G2>, ct: &BZ03_Ciphertext<PE>) -> bool {
        let mut lhs =  pair::ate( &share.data, &ECP::generator());
        lhs = pair::fexp(&lhs);

        let mut rhs = pair::ate(&ct.u, &self.verificationKey[(&share.id - 1) as usize]);
        rhs = pair::fexp(&rhs);
        
        lhs.equals(&rhs)
    }
}

// hash ECP to bit string
fn G(x: &ECP2) -> Vec<u8> {
    let mut res:Vec<u8> = vec![0;100];
    x.getx().tobytes(&mut res);

    let mut h = HASH256::new();
    h.process_array(&res);
    
    let r = h.hash().to_vec();
    r
}*/