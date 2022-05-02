use std::borrow::BorrowMut;

use derive::{PublicKey, PrivateKey, Share, Serializable};
use mcore::{hash256::HASH256};
use rasn::{AsnType, Encode, Decode};
use crate::{interface::{PrivateKey, PublicKey, Share, ThresholdSignature, ThresholdSignatureParams}, rsa_schemes::{keygen::{RsaKeyGenerator, RsaPrivateKey, RsaScheme}, bigint::BigInt, common::{interpolate, ext_euclid}}, unwrap_keys, BIGINT, rand::{RNG, RngAlgorithm}};

#[derive(PublicKey, AsnType, Clone)]
pub struct Sh00PublicKey {
    N: BigInt,
    e: BigInt,
    verificationKey:Sh00VerificationKey,
    delta:usize,
    modbits:usize
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

impl Encode for Sh00PublicKey {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        todo!()
    }
}

impl Decode for Sh00PublicKey {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        todo!()
    }
}

impl PartialEq for Sh00PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.N == other.N && self.e == other.e && self.verificationKey == other.verificationKey && self.delta == other.delta && self.modbits == other.modbits
    }
}

#[derive(PrivateKey, AsnType, Clone)]
pub struct Sh00PrivateKey {
    id: u32,
    m: BigInt,
    si: BigInt,
    pubkey: Sh00PublicKey
}

impl Sh00PrivateKey {
    pub fn new(id: u32,
        m: BigInt,
        si: BigInt,
        pubkey: Sh00PublicKey) -> Self {
        Self {id, m, si, pubkey}
    }
}

impl Encode for Sh00PrivateKey {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        todo!()
    }
}

impl Decode for Sh00PrivateKey {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        todo!()
    }
}

impl PartialEq for Sh00PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.m == other.m && self.si == other.si && self.pubkey == other.pubkey
    }
}

#[derive(Share, AsnType, Clone)]
pub struct Sh00SignatureShare {
    id:u32,
    label:Vec<u8>,
    xi:BigInt,
    z:BigInt,
    c:BigInt
}

impl Sh00SignatureShare {
    pub fn get_id(&self) -> u32 {
        self.id.clone()
    }

    pub fn get_data(&self) -> BigInt {
        self.xi.clone()
    }
}

impl Encode for Sh00SignatureShare {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        todo!()
    }
}

impl Decode for Sh00SignatureShare {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        todo!()
    }
}

impl PartialEq for Sh00SignatureShare {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.label == other.label && self.xi == other.xi && self.z == other.z && self.c == other.c
    }
}

#[derive(Clone, AsnType, Serializable)]
pub struct Sh00SignedMessage {
    msg: Vec<u8>,
    sig: BigInt
}

impl Sh00SignedMessage {
    pub fn get_sig(&self) -> BigInt {
        self.sig.clone()
    }
}

impl Encode for Sh00SignedMessage {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        todo!()
    }
}

impl Decode for Sh00SignedMessage {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        todo!()
    }
}

impl PartialEq for Sh00SignedMessage {
    fn eq(&self, other: &Self) -> bool {
        self.msg == other.msg && self.sig == other.sig
    }
}

#[derive(Clone, AsnType, Serializable)]
pub struct Sh00VerificationKey {
    v: BigInt,
    vi: Vec<BigInt>,
    u: BigInt
}

impl Sh00VerificationKey {
    pub fn new(v: BigInt,
        vi: Vec<BigInt>,
        u: BigInt) -> Self {
            Self{ v, vi, u}
        }
}

impl Encode for Sh00VerificationKey {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        todo!()
    }
}

impl Decode for Sh00VerificationKey {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        todo!()
    }
}

impl PartialEq for Sh00VerificationKey {
    fn eq(&self, other: &Self) -> bool {
        self.v == other.v && self.vi == other.vi && self.u == other.u
    }
}

pub struct Sh00ThresholdSignature {
}


impl ThresholdSignature for Sh00ThresholdSignature {
    type TSig = Sh00SignedMessage;

    type TPubKey = Sh00PublicKey;

    type TPrivKey = Sh00PrivateKey;

    type TShare = Sh00SignatureShare;

    fn verify(sig: &Self::TSig, pk: &Self::TPubKey) -> bool {
        sig.sig.pow_mod(&pk.e, &pk.N).equals(&H1(&sig.msg, &pk.N, pk.modbits))
    }

    fn partial_sign(msg: &[u8], label: &[u8], sk: &Self::TPrivKey, params: &mut ThresholdSignatureParams) -> Self::TShare {
        let N = sk.get_public_key().N.clone();
        let v = sk.get_public_key().verificationKey.v.clone();
        let vi = sk.get_public_key().verificationKey.vi[(sk.id - 1) as usize].clone();
        let si = sk.si.clone();

        let (x, _) = H(&msg, &sk.get_public_key()); 
        let xi = x.pow_mod(&si.add(&si), &N); // xi = x^(2*si)

        let x_hat = x.pow_mod(&BIGINT!(4), &N); // x_hat = x^4

        
        let bits = 2*sk.pubkey.modbits + 2 + 2*8;
        let r = BigInt::new_rand(&mut params.rng, bits); // r = random in {0, 2^(2*modbits + 2 + 2*L1)}

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
        let vi = pk.verificationKey.vi[(share.id - 1) as usize].clone();
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