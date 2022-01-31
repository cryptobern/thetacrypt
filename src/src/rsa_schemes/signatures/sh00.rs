use mcore::{rand::RAND, hash256::HASH256};

use crate::{interface::{PrivateKey, PublicKey, Share, ThresholdSignature}, rsa_schemes::{keygen::{RsaKeyGenerator, RsaPrivateKey, RsaScheme}, bigint::BigInt, common::{interpolate, ext_euclid}}, unwrap_keys, BIGINT};


const BigInt_BYTES:usize = 2048;
const L1:usize = 32*8;

pub struct SH00_ThresholdSignature {
    g: BigInt
}

pub struct SH00_SignatureShare {
    id:usize,
    label:Vec<u8>,
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
    modbits:usize
}  

pub struct SH00_PrivateKey {
    id: usize,
    m: BigInt,
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
        sig.sig.pow_mod(&pk.e, &pk.N).equals(&H1(&sig.msg, &pk.N, pk.modbits))
    }

    fn partial_sign(msg: &[u8], sk: &Self::SK) -> Self::SH {
        let N = sk.get_public_key().N.clone();
        let v = sk.get_public_key().verificationKey.v.clone();
        let vi = sk.get_public_key().verificationKey.vi[sk.id - 1].clone();

        let (x, _) = H(&msg, &sk.get_public_key()); 
        let xi = x.pow_mod(&sk.si.lshift(1), &N); // xi = x^(2*si)

        let x_hat = x.pow(4).rmod(&N); // x_hat = x^4

        // L(n) = bit length of n
        let r = BIGINT!(777777777777777777); //TODO: random value in {0, 2^(2*modbits + 2 + 2*L1)}

        let v1 = v.pow_mod(&r, &N); //v1 = v^r

        let x1 = x_hat.pow_mod(&r, &N); // x1 = x_hat^r

        let xi2 = xi.pow(2).rmod(&N); //xi2 = xi^2

       // println!("v1: {}", v1.to_string());

        let c = H2(&v, &x_hat, &vi, &xi2, &v1, &x1);

        let z = sk.si.mul(&c).add(&r); // z = si*c + r

        return Self::SH {id: sk.get_id(), label:b"".to_vec(), xi:xi, z, c }
    }

    fn verify_share(share: &Self::SH, msg: &[u8], pk: &Self::PK) -> bool {
        let N = pk.N.clone();
        let v = pk.verificationKey.v.clone();
        let vi = pk.verificationKey.vi[share.id - 1].clone();
        let (x, _) = H(&msg,  &pk);
        let z = share.z.clone();
        let c = share.c.clone();
        let xi = share.get_data();

        let x_hat = x.pow(4).rmod(&N); // x_hat = x^4

        let xi2 = share.xi.pow(2); //xi2 = xi^2

        let T = vi.pow_mod(&c, &N).inv_mod(&N);
        let v1 = v.pow_mod(&z, &N).mul_mod(&T, &N); // v1 = v^z*vi^(-c) 

        let T = xi.pow_mod(&c.lshift(1), &N).inv_mod(&N);
        let x1 = x_hat.pow_mod(&z, &N).mul_mod(&T, &N);  // x1 = x_hat^z*xi^(-2c)

       // println!("v1: {}", v1.to_string());

        let c = H2(&v, &x_hat, &vi, &xi2, &v1, &x1);

        c.equals(&share.c)
    }

    fn assemble(shares: &Vec<Self::SH>, msg: &[u8], pk: &Self::PK) -> Self::SM {
        let u = pk.verificationKey.u.clone();
        let N = pk.N.clone();

        let (a, b) = ext_euclid(&BIGINT!(4), &pk.e); // 4*a + e*b = 1

        let (x, j) = H(&msg, &pk);
        
        let w = interpolate(&shares, &pk.N, pk.delta).pow_mod(&a, &N);

        let mut y = w.mul_mod(&x.pow_mod( &b, &pk.N), &pk.N); // y = w^a * x^b
        
        if j == -1 {
            y = u.inv_mod(&pk.N).mul_mod(&y, &N);
        }

        SH00_SignedMessage{sig:y, msg:msg.to_vec()} 
    }
}

impl SH00_ThresholdSignature {
    pub fn generate_keys(k: usize, n: usize, modsize: usize, rng: &mut impl RAND) -> Vec<SH00_PrivateKey> {
        let keys = RsaKeyGenerator::generate_keys(k, n, rng, RsaScheme::SH00(modsize));
        unwrap_keys!(keys, RsaPrivateKey::SH00)
    }
}

impl PublicKey for SH00_PublicKey {}

impl SH00_PublicKey {
    pub fn new(N: BigInt,
        e: BigInt,
        verificationKey:SH00_VerificationKey,
        delta:usize,
        modbits:usize) -> Self {
        Self {N, e, verificationKey, delta, modbits}
    }
}

impl SH00_SignatureShare {
    pub fn get_id(&self) -> usize {
        self.id.clone()
    }

    pub fn get_data(&self) -> BigInt {
        self.xi.clone()
    }
}

impl Clone for SH00_SignatureShare {
    fn clone(&self) -> Self {
        Self { id: self.id.clone(), label: self.label.clone(), xi: self.xi.clone(), z: self.z.clone(), c: self.c.clone() }
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
        m: BigInt,
        si: BigInt,
        pubkey: SH00_PublicKey) -> Self {
        Self {id, m, si, pubkey}
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
        Self { N: self.N.clone(), e: self.e.clone(), verificationKey: self.verificationKey.clone(), delta: self.delta.clone(), modbits: self.modbits.clone() }
    }
}
impl Clone for SH00_PrivateKey {
    fn clone(&self) -> Self {
        Self { id: self.id.clone(), m: self.m.clone(), si: self.si.clone(), pubkey: self.pubkey.clone() }
    }
}

impl Clone for SH00_VerificationKey {
    fn clone(&self) -> Self {
        Self { v: self.v.clone(), vi: self.vi.clone(), u: self.u.clone() }
    }
}

fn H(m: &[u8], pk: &SH00_PublicKey) -> (BigInt, isize) {
    let mut x = H1(m, &pk.N, pk.modbits);
    let j = BigInt::jacobi(&x, &pk.N);
    if j == -1 {
        x = pk.verificationKey.u.pow_mod(&pk.e, &pk.N).mul_mod(&x, &pk.N); // x = x * u^e
    } else if j == 0 {
        panic!("jacobi(x, n) == 0"); //TODO: make sure j != 0 by changing hash function H1
    }

    (x, j)
}

// TODO: improve hash function
fn H1(m: &[u8], n: &BigInt, modbits:usize) -> BigInt {
    let mut hash = HASH256::new();
    hash.process_array(&m);
    let h = hash.hash();

    let mut buf = Vec::new();
    buf = [&buf[..], &h].concat();
    
    if modbits > buf.len()*4 {
        let mut g:[u8;32];
        for i in 1..(((modbits - buf.len()*4)/buf.len()) as f64).ceil() as isize {
            g = h.clone();
            hash.process_array(&[&g[..], &(i.to_ne_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    BigInt::from_bytes(&mut buf).rmod(&n)
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