#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use miracl_core::rand::RAND;
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::big;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::rom;
use miracl_core::bls12381::pair;
use miracl_core::hmac::*;
use miracl_core::aes::*;
use miracl_core::hash256::*;

use crate::threshold::*;

pub struct BZ03_PublicKey {
    y: ECP2,
    verificationKey: Vec<ECP>,
    group: ECGroup,
}

impl Clone for BZ03_PublicKey {
    fn clone(&self) -> BZ03_PublicKey {
        return BZ03_PublicKey {y:self.y.clone(), verificationKey:self.verificationKey.clone(), group:ECGroup { q:self.group.q.clone(), g: ECP::generator() }};
    }
}

pub struct BZ03_PrivateKey {
    id: u8,
    xi: BIG,
    pubkey: BZ03_PublicKey,
}


pub fn bz03_gen_keys(k: u8, n:u8, rng: &mut impl RAND) -> (BZ03_PublicKey, Vec<BZ03_PrivateKey>) {
    let x = BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng);
    let mut y = ECP2::generator();
    y = y.mul(&x);

    let s = BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng);

    let (shares, h) = shamir_share(&x, &ECP::generator(), &k, &n, rng);
    let pk = BZ03_PublicKey {y:y.clone(), verificationKey:h.clone(), group:ECGroup { q:BIG::new_ints(&rom::CURVE_ORDER), g:ECP::generator() }};
    let mut sk: Vec<BZ03_PrivateKey> = Vec::new();
    
    for j in 1..n+1 {
        sk.push(BZ03_PrivateKey {id:j, xi:shares[(j -1) as usize], pubkey:pk.clone()});
    }

    (pk, sk)
}  

impl BZ03_PrivateKey {
    pub fn partial_decrypt(&self, ct: &BZ03_Ciphertext) -> BZ03_DecryptionShare {
        let mut u = ct.u.clone();
        u = u.mul(&self.xi);

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

impl BZ03_PublicKey {
    pub fn encrypt(&self, msg:Vec<u8>, label:Vec<u8>, rng: &mut impl RAND) -> BZ03_Ciphertext {
        let prk: &mut [u8] = &mut[0;32];
        let mut ikm: Vec<u8> = Vec::new();
        for _ in 0..32 {
            ikm.push(rng.getbyte());
        }

        let salt: Vec<u8> = Vec::new();
        hkdf_extract(MC_SHA2, 32, prk, Option::Some(&salt), &ikm);

        let k: &mut[u8] = &mut[0;32];
        hkdf_expand(MC_SHA2, 32, k, 16, prk, &[0]);

        let q = BIG::new_ints(&rom::CURVE_ORDER);
        let r = BIG::randomnum(&q, rng);
        let mut u = ECP2::generator();
        u = u.mul(&r);

        let mut rY = self.y.clone();
        rY = rY.mul(&r);

        let c_k = xor(G(&rY), (*k).to_vec());

        let mut encryption: Vec<u8> = vec![0; msg.len()];
        cbc_iv0_encrypt(k, &msg, &mut encryption);

        let hr = H(&u, &encryption).mul(&r);

        let c = BZ03_Ciphertext{label:label, msg:encryption, c_k:c_k.to_vec(), u:u, hr:hr};
        c
    }


    pub fn assemble(&self, ct:&BZ03_Ciphertext, shares:&Vec<BZ03_DecryptionShare>) -> Vec<u8> {
        let rY = interpolate_exp(shares);

        let key = xor(G(&rY), ct.c_k.clone());
        
        let mut msg: Vec<u8> = vec![0; 44];
        cbc_iv0_decrypt(&key, &ct.msg.clone(), &mut msg);

        msg
    }

    pub fn verify_ciphertext(&self, ct: &BZ03_Ciphertext) -> bool {
        let h = H(&ct.u, &ct.msg);

        let mut lhs =  pair::ate(&ct.u, &h);
        lhs = pair::fexp(&lhs);

        let mut rhs = pair::ate(&ECP2::generator(), &ct.hr);
        rhs = pair::fexp(&rhs);
        
        lhs.equals(&rhs)
    }

    pub fn verify_decryption_share(&self, share: &BZ03_DecryptionShare, ct: &BZ03_Ciphertext) -> bool {
        let mut lhs =  pair::ate( &share.data, &ECP::generator());
        lhs = pair::fexp(&lhs);

        let mut rhs = pair::ate(&ct.u, &self.verificationKey[(&share.id - 1) as usize]);
        rhs = pair::fexp(&rhs);
        
        lhs.equals(&rhs)
    }
}

fn xor(v1: Vec<u8>, v2: Vec<u8>) -> Vec<u8> {
    let v3: Vec<u8> = v1
    .iter()
    .zip(v2.iter())
    .map(|(&x1, &x2)| x1 ^ x2)
    .collect();

    v3
}

// hash ECP to bit string
fn G(x: &ECP2) -> Vec<u8> {
    let mut res:Vec<u8> = vec![0;100];
    x.getx().tobytes(&mut res);

    let mut h = HASH256::new();
    h.process_array(&res);
    
    let r = h.hash().to_vec();
    r
}

pub struct BZ03_DecryptionShare {
    id: u8,
    data: ECP2
}

impl DecryptionShare for BZ03_DecryptionShare {
    fn get_id(&self) -> u8 { self.id.clone() }
    fn get_data(&self) -> ECP2 { self.data.clone() }
}

pub struct BZ03_Ciphertext {
    label: Vec<u8>,
    msg: Vec<u8>,
    c_k: Vec<u8>,
    u: ECP2,
    hr: ECP
}

impl Ciphertext for BZ03_Ciphertext {
    fn get_msg(&self) -> Vec<u8> { self.msg.clone() }
    fn get_label(&self) -> Vec<u8> { self.label.clone() }
}