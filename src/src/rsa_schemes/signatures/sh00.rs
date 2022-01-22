use mcore::{rand::RAND, hash256::HASH256};

use crate::{interface::{PrivateKey, PublicKey, Share, ThresholdSignature}, rsa_schemes::{keygen::{RsaKeyGenerator, RsaPrivateKey, RsaScheme}, rsa_mod::RsaModulus, bigint::BigInt, common::{interpolate, ext_euclid}}, unwrap_keys, BIGINT};


const BigInt_BYTES:usize = 2048;
const L1:usize = 32*8;

pub struct SH00_ThresholdSignature {
    g: BigInt
}

pub struct SH00_SignatureShare {
    id:usize,
    label:Vec<u8>,
    delta:usize,
    xi:BigInt,
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
    si: BigInt,
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
        BigInt::_pow_mod(&sig.sig, &pk.e, &pk.N).equals(&H1(&sig.msg, &pk.N, pk.plen))
    }

    fn partial_sign(msg: &[u8], sk: &Self::SK) -> Self::SH {
        let N = sk.get_public_key().N.clone();
        let v = sk.get_public_key().verificationKey.v.clone();
        let vi = sk.get_public_key().verificationKey.vi[sk.id - 1].clone();

        let (x, _) = H(&msg, &sk.get_public_key()); 
        let xi = BigInt::_pow_mod(&x, &BigInt::_imul(&sk.si, 2), &N); // xi = x^(2*si)

        let mut x_hat = x.clone();
        x_hat.pow(4);
        x_hat.rmod(&N); // x_hat = x^4

        // L(n) = bit length of n
        let r = BIGINT!(777777); //TODO: random value in {0, 2^(2*plen + 2 + 2*L1)}

        let mut v1 = v.clone();
        v1.pow_mod(&r, &N); //v1 = v^r

        let mut x1 = x_hat.clone();
        x1.pow_mod(&r, &N); // x1 = x_hat^r

        let xi2 = BigInt::_pow(&xi, 2); //xi2 = xi^2

        let c = H2(&v, &x_hat, &vi, &xi2, &v1, &x1);

        let mut z = BigInt::_mul(&sk.si, &c);
        z.add(&r);  // z = si*c + r

        return Self::SH {id: sk.get_id(), label:b"".to_vec(), delta:sk.get_public_key().delta, xi:xi, z, c }
    }

    fn verify_share(share: &Self::SH, msg: &[u8], pk: &Self::PK) -> bool {
        let N = pk.N.clone();
        let v = pk.verificationKey.v.clone();
        let vi = pk.verificationKey.vi[share.id - 1].clone();
        let (x, _) = H(&msg,  &pk);
        let z = share.z.clone();

        let mut neg_c = share.c.clone();
        neg_c.rmod(&N);
        neg_c = BigInt::_sub(&N, &neg_c); // neg_c = (-c) mod N

        let mut x_hat = x.clone();
        x_hat.pow(4);
        x_hat.rmod(&N); // x_hat = x^4

        let xi2 = BigInt::_pow(&share.xi, 2); //xi2 = xi^2

        let vz = BigInt::_pow_mod(&v, &z, &N);
        let vineg_c =  BigInt::_pow_mod(&vi, &neg_c, &N);
        let v1 = BigInt::_mul_mod(&vz, &vineg_c, &N);  // v1 = v^z*vi^(-c) 

        let x_hatz = BigInt::_pow_mod(&x_hat, &z, &N);
        let xi2neg_c =  BigInt::_pow_mod(&vi, &BigInt::_imul(&neg_c, 2), &N);
        let x1 = BigInt::_mul_mod(&x_hatz, &xi2neg_c, &N);  // x1 = x_hat^z*xi^(-2c)

        let c = H2(&v, &x_hat, &vi, &xi2, &v1, &x1);

        c.equals(&share.c)
    }

    fn assemble(shares: &Vec<Self::SH>, msg: &[u8], pk: &Self::PK) -> Self::SM {
        let (mut x, j) = H(&msg, &pk);
        
        let mut w = interpolate(&shares, &pk.N);

        let e1 = BIGINT!(4);
        let (a, b) = ext_euclid(&e1, &pk.e);

        let check = BigInt::_pow_mod(&w, &pk.e, &pk.N);
        let check1 = BigInt::_pow_mod(&x, &e1, &pk.N);
        println!("check: {}\n{}", check.to_string(), check1.to_string());

        w.pow_mod(&a, &pk.N);
        x.pow_mod(&b, &pk.N);

        let mut sig = BigInt::_mul_mod(&w, &x, &pk.N);
        
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
        self.xi.clone()
    }

    pub fn get_delta(&self) -> usize {
        return self.delta;
    }
}

impl Clone for SH00_SignatureShare {
    fn clone(&self) -> Self {
        Self { id: self.id.clone(), label: self.label.clone(), delta: self.delta.clone(), xi: self.xi.clone(), z: self.z.clone(), c: self.c.clone() }
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
        si: BigInt,
        pubkey: SH00_PublicKey) -> Self {
        Self {id, modulus, si, pubkey}
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
        Self { id: self.id.clone(), modulus: self.modulus.clone(), si: self.si.clone(), pubkey: self.pubkey.clone() }
    }
}

impl Clone for SH00_VerificationKey {
    fn clone(&self) -> Self {
        Self { v: self.v.clone(), vi: self.vi.clone(), u: self.u.clone() }
    }
}

fn H(m: &[u8], pk: &SH00_PublicKey) -> (BigInt, isize) {
    let mut x = H1(m, &pk.N, pk.plen);
    let j = BigInt::jacobi(&x, &pk.N);

    println!("{}", x.to_string());

    if j == -1 {
        let tmp = BigInt::_pow_mod(&pk.verificationKey.u, &pk.e, &pk.N);
        x.mul_mod(&tmp, &pk.N);
    } else if j == 0 {
        panic!("jacobi(x, n) == 0"); //TODO: make sure j != 0 by changing hash function H1
    }

    (x, j)
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

fn H2(g1: &BigInt, g2: &BigInt, g3: &BigInt, g4: &BigInt, g5: &BigInt, g6: &BigInt) -> BigInt {
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

    BigInt::from_bytes(&mut buf)
}