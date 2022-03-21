use std::borrow::BorrowMut;

use mcore::{hash256::HASH256};
use crate::{interface::{PrivateKey, PublicKey, Share, ThresholdSignature}, rsa_schemes::{keygen::{RsaKeyGenerator, RsaPrivateKey, RsaScheme}, bigint::BigInt, common::{interpolate, ext_euclid}}, unwrap_keys, BIGINT, rand::{RNG, RngAlgorithm}};


pub struct Sh00ThresholdSignature {
}

pub struct Sh00SignatureShare {
    id:usize,
    label:Vec<u8>,
    xi:BigInt,
    z:BigInt,
    c:BigInt
}

pub struct Sh00SignedMessage {
    msg: Vec<u8>,
    sig: BigInt
}

pub struct Sh00PublicKey {
    N: BigInt,
    e: BigInt,
    verificationKey:Sh00VerificationKey,
    delta:usize,
    modbits:usize
}  

pub struct Sh00PrivateKey {
    id: usize,
    m: BigInt,
    si: BigInt,
    pubkey: Sh00PublicKey
}

pub struct Sh00VerificationKey {
    v: BigInt,
    vi: Vec<BigInt>,
    u: BigInt
}

pub struct Sh00Params {
    rng: RNG
}

impl Sh00Params {
    pub fn new(alg: RngAlgorithm) -> Self {
        let rng = RNG::new(alg);
        Self { rng }
    }
}

impl ThresholdSignature for Sh00ThresholdSignature {
    type TSig = Sh00SignedMessage;

    type TPubKey = Sh00PublicKey;

    type TPrivKey = Sh00PrivateKey;

    type TShare = Sh00SignatureShare;

    type TParams = Sh00Params;

    fn verify(sig: &Self::TSig, pk: &Self::TPubKey) -> bool {
        sig.sig.pow_mod(&pk.e, &pk.N).equals(&H1(&sig.msg, &pk.N, pk.modbits))
    }

    fn partial_sign(msg: &[u8], label: &[u8], sk: &Self::TPrivKey, params: Option<&mut Sh00Params>) -> Self::TShare {
        if params.is_none() {
            panic!("no random number generator provided!");
        }

        let N = sk.get_public_key().N.clone();
        let v = sk.get_public_key().verificationKey.v.clone();
        let vi = sk.get_public_key().verificationKey.vi[sk.id - 1].clone();
        let si = sk.si.clone();

        let (x, _) = H(&msg, &sk.get_public_key()); 
        let xi = x.pow_mod(&si.add(&si), &N); // xi = x^(2*si)

        let x_hat = x.pow_mod(&BIGINT!(4), &N); // x_hat = x^4

        
        let bits = 2*sk.pubkey.modbits + 2 + 2*8;
        let rng = params.unwrap().rng.borrow_mut();
        let r = BigInt::new_rand(rng, bits); // r = random in {0, 2^(2*modbits + 2 + 2*L1)}

        let v1 = v.pow_mod(&r, &N); //v1 = v^r
        let x1 = x_hat.pow_mod(&r, &N); // x1 = x_hat^r
        let xi2 = xi.pow(2).rmod(&N); //xi2 = xi^2

        let c = H2(&v, &x_hat, &vi, &xi2, &v1, &x1);

        let z = si.mul(&c).add(&r); // z = si*c + r

        return Self::TShare {id: sk.get_id(), label:label.to_vec(), xi:xi, z:z, c:c }
    }

    fn verify_share(share: &Self::TShare, msg: &[u8], pk: &Self::TPubKey) -> bool {
        let N = pk.N.clone();
        let v = pk.verificationKey.v.clone();
        let vi = pk.verificationKey.vi[share.id - 1].clone();
        let (x, _) = H(&msg,  &pk);
        let z = share.z.clone();
        let c = share.c.clone();
        let xi = share.get_data();

        let x_hat = x.pow_mod(&BIGINT!(4), &N); // x_hat = x^4

        let xi2 = share.xi.pow(2).rmod(&N); //xi2 = xi^2

        let div = vi.pow_mod(&c, &N).inv_mod(&N);
        let v1 = v.pow_mod(&z, &N).mul_mod(&div, &N); // v1 = v^z / vi^c 

        let div = xi.pow_mod(&c.add(&c), &N).inv_mod(&N);
        let x1 = x_hat.pow_mod(&z, &N).mul_mod(&div, &N);  // x1 = x_hat^z / xi^(2c)

        let c2 = H2(&v, &x_hat, &vi, &xi2, &v1, &x1);

        c2.equals(&c)
    }

    fn assemble(shares: &Vec<Self::TShare>, msg: &[u8], pk: &Self::TPubKey) -> Self::TSig {
        let u = pk.verificationKey.u.clone();
        let N = pk.N.clone();

        let (a, b) = ext_euclid(&BIGINT!(4), &pk.e); // 4*a + e*b = 1
        let (x, j) = H(&msg, &pk);
        let w = interpolate(&shares, &pk.N, pk.delta).pow_mod(&a, &N);
        let mut y = w.mul_mod(&x.pow_mod( &b, &pk.N), &pk.N); // y = w^a * x^b
        
        if j == -1 {
            y = u.inv_mod(&pk.N).mul_mod(&y, &N);
        }

        Sh00SignedMessage{sig:y, msg:msg.to_vec()} 
    }
}

impl Sh00ThresholdSignature {
    pub fn generate_keys(k: usize, n: usize, modsize: usize, rng: &mut RNG) -> Vec<Sh00PrivateKey> {
        let keys = RsaKeyGenerator::generate_keys(k, n, rng, RsaScheme::SH00(modsize));
        unwrap_keys!(keys, RsaPrivateKey::SH00)
    }
}

impl PublicKey for Sh00PublicKey {
    fn encode(&self) -> Vec<u8> {
        todo!()
    }

    fn decode(bytes: Vec<u8>) -> Self {
        todo!()
    }
}

impl Sh00PublicKey {
    pub fn new(N: BigInt,
        e: BigInt,
        verificationKey:Sh00VerificationKey,
        delta:usize,
        modbits:usize) -> Self {
        Self {N, e, verificationKey, delta, modbits}
    }
}

impl Sh00SignatureShare {
    pub fn get_id(&self) -> usize {
        self.id.clone()
    }

    pub fn get_data(&self) -> BigInt {
        self.xi.clone()
    }
}

impl Clone for Sh00SignatureShare {
    fn clone(&self) -> Self {
        Self { id: self.id.clone(), label: self.label.clone(), xi: self.xi.clone(), z: self.z.clone(), c: self.c.clone() }
    }
}

impl PrivateKey for Sh00PrivateKey {
    type TPubKey = Sh00PublicKey;

    fn get_id(&self) -> usize {
        self.id
    }

    fn get_public_key(&self) -> Self::TPubKey {
        self.pubkey.clone()
    }

    fn encode(&self) -> Vec<u8> {
        todo!()
    }

    fn decode(bytes: Vec<u8>) -> Self {
        todo!()
    }
}

impl Sh00PrivateKey {
    pub fn new(id: usize,
        m: BigInt,
        si: BigInt,
        pubkey: Sh00PublicKey) -> Self {
        Self {id, m, si, pubkey}
    }
}

impl Sh00VerificationKey {
    pub fn new(v: BigInt,
        vi: Vec<BigInt>,
        u: BigInt) -> Self {
            Self{ v, vi, u}
        }
}

impl Sh00SignedMessage {
    pub fn get_sig(&self) -> BigInt {
        self.sig.clone()
    }
}

impl Share for Sh00SignatureShare {
    fn get_id(&self) -> usize {
        self.id
    }

    fn encode(&self) -> Vec<u8> {
        todo!()
    }

    fn decode(bytes: Vec<u8>) -> Self {
        todo!()
    }
}

impl Clone for Sh00PublicKey {
    fn clone(&self) -> Self {
        Self { N: self.N.clone(), e: self.e.clone(), verificationKey: self.verificationKey.clone(), delta: self.delta.clone(), modbits: self.modbits.clone() }
    }
}
impl Clone for Sh00PrivateKey {
    fn clone(&self) -> Self {
        Self { id: self.id.clone(), m: self.m.clone(), si: self.si.clone(), pubkey: self.pubkey.clone() }
    }
}

impl Clone for Sh00VerificationKey {
    fn clone(&self) -> Self {
        Self { v: self.v.clone(), vi: self.vi.clone(), u: self.u.clone() }
    }
}

fn H(m: &[u8], pk: &Sh00PublicKey) -> (BigInt, isize) {
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

    let blen = buf.len()*4;
    let max = (((modbits - blen)/buf.len()) as f64).ceil() as isize;
    
    if modbits > blen {
        let mut g:[u8;32];
        for i in 1..max {
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