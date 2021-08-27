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

pub struct SG02_PublicKey {
    y: ECP,
    verificationKey: Vec<ECP>,
    g_hat: ECP,
    group: ECGroup,
}

impl Clone for SG02_PublicKey {
    fn clone(&self) -> SG02_PublicKey {
        return SG02_PublicKey {y:self.y.clone(), verificationKey:self.verificationKey.clone(), g_hat:self.g_hat.clone(), group:ECGroup { q:self.group.q.clone(), g: ECP::generator() }};
    }
}

pub struct SG02_PrivateKey {
    id: u8,
    xi: BIG,
    pubkey: SG02_PublicKey,
}

pub struct SG02_Ciphertext {
    label: Vec<u8>,
    msg: Vec<u8>,
    u: ECP,
    u2: ECP,
    e: BIG,
    f: BIG,
    c_k: Vec<u8>,
}

impl Ciphertext for SG02_Ciphertext {
    fn get_msg(&self) -> Vec<u8> {
        self.msg.clone()
    }

    fn get_label(&self) -> Vec<u8> {
        self.label.clone()
    }
}

pub struct SG02_DecryptionShare {
    id: u8,
    label: Vec<u8>,
    data: ECP,
    ei: BIG,
    fi: BIG,
}

pub fn sg02_gen_keys(k: u8, n:u8, rng: &mut impl RAND) -> (SG02_PublicKey, Vec<SG02_PrivateKey>) {
    let s = BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng);
    let mut g_hat = ECP::generator();
    g_hat = g_hat.mul(&s);

    let (y, shares, h) = gen_key_values(k, n, rng);
    let pk = SG02_PublicKey {y:y.clone(), verificationKey:h.clone(), g_hat:g_hat, group:ECGroup { q:BIG::new_ints(&rom::CURVE_ORDER), g:ECP::generator() }};
    let mut sk: Vec<SG02_PrivateKey> = Vec::new();
    
    for j in 1..n+1 {
        sk.push(SG02_PrivateKey {id:j, xi:shares[(j -1) as usize], pubkey:pk.clone()});
    }

    (pk, sk)
}  

impl SG02_PublicKey {
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

        let mut w2 = self.g_hat.clone();
        w2 = w2.mul(&s);

        let mut u2 = self.g_hat.clone();
        u2 = u2.mul(&r);

        let e = H1(&c_k, &label, &u, &w, &u2, &w2);

        let mut f = BIG::mul(&e, &r).dmod(&q);
        f.add(&s);

        let c = SG02_Ciphertext{label:label.clone(), msg:encryption, c_k:c_k.to_vec(), u:u, u2:u2, e:e, f:f};
        c
    }

    pub fn assemble(&self, shares: Vec<SG02_DecryptionShare>, ct: SG02_Ciphertext) -> Vec<u8> {
        vec![0; 100]
    }
}

fn H1(m1: &Vec<u8>, m2:&Vec<u8>, g1: &ECP, g2: &ECP, g3: &ECP, g4: &ECP) -> BIG {
    let mut bytes:Vec<u8>= vec![0;180];
    let mut buf:Vec<u8> = Vec::new();

    buf = [&buf[..], &m1[..]].concat();
    buf = [&buf[..], &m2[..]].concat();

    g1.tobytes(&mut bytes, true);
    buf = [&buf[..], &bytes[..]].concat();

    g2.tobytes(&mut bytes, true);
    buf = [&buf[..], &bytes[..]].concat();

    g3.tobytes(&mut bytes, true);
    buf = [&buf[..], &bytes[..]].concat();

    g4.tobytes(&mut bytes, true);
    buf = [&buf[..], &bytes[..]].concat();

    let mut h = HASH256::new();
    h.process_array(&buf);

    let mut res = BIG::frombytes(&buf);
    res.rmod(&BIG::new_ints(&rom::CURVE_ORDER));

    res
}

// hash ECP to bit string
fn H(x: &ECP) -> Vec<u8> {
    let mut res:Vec<u8> = vec![0;100];
    x.getx().tobytes(&mut res);

    let mut h = HASH256::new();
    h.process_array(&res);
    
    let r = h.hash().to_vec();
    r
}

impl SG02_PrivateKey {
    fn partial_decrypt(&self, ct: &SG02_Ciphertext, rng: &mut impl RAND) -> SG02_DecryptionShare {
        let mut data = ct.u.clone();
        data = data.mul(&self.xi);

        let q = BIG::new_ints(&rom::CURVE_ORDER);

        let si = BIG::randomnum(&q, rng);

        // TODO: calculate ZKP
        let ei =    BIG::new_int(1);
        let fi = BIG::new_int(1);

        SG02_DecryptionShare { id:self.id.clone(), data:data, label:ct.label.clone(), ei:ei, fi:fi}
    }
}