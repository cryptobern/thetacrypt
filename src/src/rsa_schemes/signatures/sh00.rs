use mcore::{rand::RAND, hash256::HASH256};

use crate::{interface::{PrivateKey, PublicKey, Share, ThresholdSignature}, rsa_schemes::{keygen::{RsaKeyGenerator, RsaPrivateKey, RsaScheme}, rsa_groups::{rsa2048::Rsa2048, rsa_domain::RsaDomain}, rsa_mod::RsaModulus, bigint::BigInt, common::{lagrange_coeff, interpolate, ext_euclid, fac}}, unwrap_keys};


const BigInt_BYTES:usize = 2048;

pub struct SH00_ThresholdSignature {
    g: BigInt
}

pub struct SH00_SignatureShare {
    id:usize,
    label:Vec<u8>,
    delta:usize,
    data:BigInt,
    z:BigInt,
    c:BigInt
}

pub struct SH00_SignedMessage {
    msg: Vec<u8>,
    sig: BigInt
}

pub struct SH00_PublicKey {
    N: BigInt,
    e: BigInt,
    verificationKey:SH00_VerificationKey,
    delta:usize,
    plen:usize
}  

pub struct SH00_PrivateKey {
    id: usize,
    modulus: RsaModulus,
    xi: BigInt,
    pubkey: SH00_PublicKey
}

pub struct SH00_VerificationKey {
    v: BigInt,
    vi: Vec<BigInt>,
    u: BigInt
}

impl ThresholdSignature for SH00_ThresholdSignature {
    type SM = SH00_SignedMessage;

    type PK = SH00_PublicKey;

    type SK = SH00_PrivateKey;

    type SH = SH00_SignatureShare;

    fn verify(sig: &Self::SM, pk: &Self::PK) -> bool {
        BigInt::_pow_mod(&sig.sig, &pk.e, &pk.N).equals(&H(&sig.msg, &pk.N, pk.plen))
    }

    fn partial_sign(msg: &[u8], sk: &Self::SK) -> Self::SH {
        let N = sk.get_public_key().N.clone();
        let e = sk.get_public_key().e.clone();
        let u = sk.get_public_key().verificationKey.u.clone();
        let v = sk.get_public_key().verificationKey.v.clone();
        let vi = sk.get_public_key().verificationKey.vi[sk.id - 1].clone();
        let h = H(&msg, &N, sk.get_public_key().plen);
        
        let j = BigInt::jacobi(&h, &N);
        let mut s = BigInt::new_copy(&h);

        if j == -1 {
            let tmp = BigInt::_pow_mod(&u, &e, &N);
            s.mul_mod(&tmp, &N);
        } else if j == 0 {
            panic!(); //TODO: make sure j != 0 by changing hash function
        }
        
        let mut exp = sk.xi.clone();
        exp.imul(2);
        let si = BigInt::_pow_mod(&s, &exp, &N);

        let e1 = BigInt::new_int(4);

        let mut s_star = s.clone();
        s_star.pow(4);
        s_star.rmod(&N);

        let r = BigInt::new_int(777777); //TODO: random value
        let mut v1 = v.clone();
        v1.pow_mod(&r, &N);

        let mut s_hat = s.clone();
        s_hat.pow(4);
        s_hat.rmod(&N);

        let mut s1 = s_hat.clone();
        s1.pow_mod(&r, &N);

        let mut si2 = si.clone();
        si2.pow(2);
        si2.rmod(&N);

        let c = H2(&v, &s_hat, &vi, &si2, &v1, &s1, &N, sk.get_public_key().plen);

        let mut z = BigInt::_mul(&sk.xi, &c);
        z.add(&r);

        return Self::SH {id: sk.get_id(), label:b"".to_vec(), delta:sk.get_public_key().delta, data:si, z, c }
    }

    fn verify_share(share: &Self::SH, msg: &[u8], pk: &Self::PK) -> bool {
        let N = pk.N.clone();
        let e = pk.e.clone();
        let u = pk.verificationKey.u.clone();
        let v = pk.verificationKey.v.clone();
        let vi = pk.verificationKey.vi[share.id - 1].clone();
        let h = H(&msg, &N, pk.plen);
        let j = BigInt::jacobi(&h, &N);
        let mut s = BigInt::new_copy(&h);

        if j == -1 {
            let tmp = BigInt::_pow_mod(&u, &e, &N);
            s.mul_mod(&tmp, &N);
        } else if j == 0 {
            panic!(); //TODO: make sure j != 0 by changing hash function
        }

        let mut s_star = s.clone();
        s_star.pow(4);
        s_star.rmod(&N);

        let r = BigInt::new_int(777777); //TODO: random value
        let mut v1 = v.clone();
        v1.pow_mod(&r, &N);

        let mut s_hat = s.clone();
        s_hat.pow(4);
        s_hat.rmod(&N);

        let mut s1 = s_hat.clone();
        s1.pow_mod(&r, &N);

        let mut si2 = share.data.clone();
        si2.pow(2);
        si2.rmod(&N);

        let c1 = H2(&v, &s_hat, &vi, &si2, &v1, &s1, &N, pk.plen);

        c1.equals(&share.c)
    }

    fn assemble(shares: &Vec<Self::SH>, msg: &[u8], pk: &Self::PK) -> Self::SM {
        let mut h = H(&msg, &pk.N, pk.plen);
        let j = BigInt::jacobi(&h, &pk.N);
        let mut s = BigInt::new_copy(&h);

        if j == -1 {
            let tmp = BigInt::_pow_mod(&pk.verificationKey.u, &pk.e, &pk.N);
            s = BigInt::_mul(&s, &tmp);
        } else if j == 0 {
            panic!(); //TODO: make sure j != 0 by changing hash function
        }

        let mut w = interpolate(&shares, &pk.N);
        let (a, b) = ext_euclid(&BigInt::new_int(4), &pk.e);

        w.pow_mod(&a, &pk.N);
        h.pow_mod(&b, &pk.N);

        let mut sig = BigInt::_mul_mod(&w, &h, &pk.N);
        
        if j == -1 {
            let u_inv = BigInt::_inv_mod(&pk.verificationKey.u, &pk.N);
            sig.mul(&u_inv);
        }

        SH00_SignedMessage{sig, msg:msg.to_vec()} 
    }
}

impl SH00_ThresholdSignature {
    pub fn generate_keys(k: usize, n: usize, psize: usize, rng: &mut impl RAND) -> Vec<SH00_PrivateKey> {
        let keys = RsaKeyGenerator::generate_keys(k, n, rng, RsaScheme::SH00(psize));
        unwrap_keys!(keys, RsaPrivateKey::SH00)
    }
}

impl PublicKey for SH00_PublicKey {}

impl SH00_PublicKey {
    pub fn new(N: BigInt,
        e: BigInt,
        verificationKey:SH00_VerificationKey,
        delta:usize,
        plen:usize) -> Self {
        Self {N, e, verificationKey, delta, plen}
    }
}

impl SH00_SignatureShare {
    pub fn get_id(&self) -> usize {
        self.id.clone()
    }

    pub fn get_data(&self) -> BigInt {
        self.data.clone()
    }

    pub fn get_delta(&self) -> usize {
        return self.delta;
    }
}

impl Clone for SH00_SignatureShare {
    fn clone(&self) -> Self {
        Self { id: self.id.clone(), label: self.label.clone(), delta: self.delta.clone(), data: self.data.clone(), z: self.z.clone(), c: self.c.clone() }
    }
}

impl PrivateKey for SH00_PrivateKey {
    type PK = SH00_PublicKey;

    fn get_id(&self) -> usize {
        self.id
    }

    fn get_public_key(&self) -> Self::PK {
        self.pubkey.clone()
    }
}

impl SH00_PrivateKey {
    pub fn new(id: usize,
        modulus: RsaModulus,
        xi: BigInt,
        pubkey: SH00_PublicKey) -> Self {
        Self {id, modulus, xi, pubkey}
    }
}

impl SH00_VerificationKey {
    pub fn new(v: BigInt,
        vi: Vec<BigInt>,
        u: BigInt) -> Self {
            Self{ v, vi, u}
        }
}

impl SH00_SignedMessage {
    pub fn get_sig(&self) -> BigInt {
        self.sig.clone()
    }
}

impl Share for SH00_SignatureShare {
    fn get_id(&self) -> usize {
        self.id
    }
}

impl Clone for SH00_PublicKey {
    fn clone(&self) -> Self {
        Self { N: self.N.clone(), e: self.e.clone(), verificationKey: self.verificationKey.clone(), delta: self.delta.clone(), plen: self.plen.clone() }
    }
}
impl Clone for SH00_PrivateKey {
    fn clone(&self) -> Self {
        Self { id: self.id.clone(), modulus: self.modulus.clone(), xi: self.xi.clone(), pubkey: self.pubkey.clone() }
    }
}

impl Clone for SH00_VerificationKey {
    fn clone(&self) -> Self {
        Self { v: self.v.clone(), vi: self.vi.clone(), u: self.u.clone() }
    }
}

fn H(m: &[u8], n: &BigInt, plen:usize) -> BigInt {
    let mut hash = HASH256::new();
    hash.process_array(&m);
    let h = hash.hash();

    let mut buf = Vec::new();
    buf = [&buf[..], &h].concat();
    
    let nbits = plen*plen;
    
    if nbits > buf.len()*4 {
        let mut g:[u8;32];
        for i in 1..(((nbits - buf.len()*4)/buf.len()*8) as f64).ceil() as isize {
            g = h.clone();
            hash.process_array(&[&g[..], &(i.to_ne_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    let mut res = BigInt::from_bytes(&mut buf);
    res.rmod(&n);

    res
}

fn H1(m: &[u8], n: &BigInt, plen:usize) -> BigInt {
    let mut hash = HASH256::new();
    hash.process_array(&m);
    let h = hash.hash();

    let mut buf = Vec::new();
    buf = [&buf[..], &h].concat();
    
    let nbits = plen*plen;
    
    if nbits > buf.len()*4 {
        let mut g:[u8;32];
        for i in 1..(((nbits - buf.len()*4)/buf.len()*8) as f64).ceil() as isize {
            g = h.clone();
            hash.process_array(&[&g[..], &(i.to_ne_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    let mut res = BigInt::from_bytes(&mut buf);
    res.rmod(&n);

    res
}

fn H2(g1: &BigInt, g2: &BigInt, g3: &BigInt, g4: &BigInt, g5: &BigInt, g6: &BigInt, n: &BigInt, plen:usize) -> BigInt {
    let mut buf:Vec<u8> = Vec::new();

    buf = [&buf[..], &g1.to_bytes()[..]].concat();
    buf = [&buf[..], &g2.to_bytes()[..]].concat();
    buf = [&buf[..], &g3.to_bytes()[..]].concat();
    buf = [&buf[..], &g4.to_bytes()[..]].concat();
    buf = [&buf[..], &g5.to_bytes()[..]].concat();
    buf = [&buf[..], &g6.to_bytes()[..]].concat();

    let mut hash = HASH256::new();
    hash.process_array(&buf);
    let h = hash.hash();

    buf = Vec::new();
    buf = [&buf[..], &h].concat();

    let nbits = plen*plen;
    
    if nbits > buf.len()*4 {
        let mut g:[u8;32];
        for i in 1..(((nbits - buf.len()*4)/buf.len()*8) as f64).ceil() as isize {
            g = h.clone();
            hash.process_array(&[&g[..], &(i.to_ne_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    let mut res = BigInt::from_bytes(&mut buf);
    res.rmod(n);

    res
}