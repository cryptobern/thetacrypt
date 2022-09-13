use std::borrow::BorrowMut;

use derive::{PublicKey, PrivateKey, DlShare, Serializable};
use mcore::{hash256::HASH256};
use rasn::{AsnType, Encode, Decode};
use crate::{interface::{ThresholdSignature, ThresholdSignatureParams, ThresholdCryptoError}, rsa_schemes::{ common::{interpolate, ext_euclid}, bigint::RsaBigInt}, BIGINT, rand::{RNG, RngAlgorithm}, unwrap_enum_vec, proto::scheme_types::{Group, ThresholdScheme}};

#[derive(AsnType, Clone, Debug, Serializable)]
pub struct Sh00PublicKey {
    t: u16,
    N: RsaBigInt,
    e: RsaBigInt,
    verification_key:Sh00VerificationKey,
    delta:usize,
    modbits:usize
}  

impl Sh00PublicKey {
    pub fn new(t:u16,
        N: RsaBigInt,
        e: RsaBigInt,
        verification_key:Sh00VerificationKey,
        delta:usize,
        modbits:usize) -> Self {
        Self {t, N, e, verification_key: verification_key, delta, modbits}
    }

    pub fn get_threshold(&self) -> u16 {
        return self.t;
    }

    pub fn get_modbits(&self) -> usize {
        return self.modbits;
    }

    pub fn get_group(&self) -> Group {
        match self.modbits {
            512 => Group::Rsa512,
            1024 => Group::Rsa1024,
            2046 => Group::Rsa2048,
            4096 => Group::Rsa4096,
            _ => panic!("invalid modbits value")
        }
    }
}

impl Encode for Sh00PublicKey {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.t.encode(sequence)?;
            self.N.encode(sequence)?;
            self.e.encode(sequence)?;
            self.verification_key.encode(sequence)?;
            self.delta.encode(sequence)?;
            self.modbits.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Sh00PublicKey {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let t = u16::decode(sequence)?;
            let N = RsaBigInt::decode(sequence)?;
            let e = RsaBigInt::decode(sequence)?;
            let verification_key = Sh00VerificationKey::decode(sequence)?;
            let delta = usize::decode(sequence)?;
            let modbits = usize::decode(sequence)?;

            Ok(Self{t, N, e, verification_key: verification_key, delta, modbits})
        })
    }
}

impl PartialEq for Sh00PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.N.equals(&other.N) && self.e.equals(&other.e) && self.verification_key.eq(&other.verification_key) 
        && self.delta == other.delta && self.modbits == other.modbits
    }
}

#[derive(AsnType, Clone, Debug, Serializable)]
pub struct Sh00PrivateKey {
    id: u16,
    m: RsaBigInt,
    si: RsaBigInt,
    pubkey: Sh00PublicKey
}

impl Sh00PrivateKey {
    pub fn new(id: u16,
        m: RsaBigInt,
        si: RsaBigInt,
        pubkey: Sh00PublicKey) -> Self {
        Self {id, m, si, pubkey}
    }

    pub fn get_public_key(&self) -> Sh00PublicKey {
        return self.pubkey.clone();
    }

    pub fn get_id(&self) -> u16 {
        return self.id;
    }

    pub fn get_threshold(&self) -> u16 {
        return self.pubkey.get_threshold();
    }

    pub fn get_group(&self) -> Group {
        return self.pubkey.get_group();
    }
}

impl Encode for Sh00PrivateKey {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.id.encode(sequence)?;
            self.m.to_bytes().encode(sequence)?;
            self.si.to_bytes().encode(sequence)?;
            self.pubkey.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Sh00PrivateKey {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let id = u16::decode(sequence)?;
            let mut m_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let mut si_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let pubkey = Sh00PublicKey::decode(sequence)?;

            let m = RsaBigInt::from_bytes(&mut m_bytes);
            let si = RsaBigInt::from_bytes(&mut si_bytes);
            Ok(Self {id, m, si, pubkey})
        })
    }
}

impl PartialEq for Sh00PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.m.equals(&other.m) && self.si.equals(&other.si) && self.pubkey.eq(&other.pubkey)
    }
}

#[derive(AsnType, Clone, Debug, Serializable)]
pub struct Sh00SignatureShare {
    group:Group,
    id:u16,
    label:Vec<u8>,
    xi:RsaBigInt,
    z:RsaBigInt,
    c:RsaBigInt
}

impl Sh00SignatureShare {
    pub fn get_id(&self) -> u16 {
        self.id.clone()
    }

    pub fn get_data(&self) -> RsaBigInt {
        self.xi.clone()
    }

    pub fn get_label(&self) -> Vec<u8> {
        self.label.clone()
    }

    pub fn get_group(&self) -> Group {
        self.group.clone()
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        ThresholdScheme::Sh00
    }
}

impl Encode for Sh00SignatureShare {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.id.encode(sequence)?;
            self.group.get_code().encode(sequence)?;
            self.label.encode(sequence)?;
            self.xi.encode(sequence)?;
            self.z.encode(sequence)?;
            self.c.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Sh00SignatureShare {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let id = u16::decode(sequence)?;
            let group = Group::from_code(u8::decode(sequence)?);
            let label = Vec::<u8>::decode(sequence)?;
            let xi = RsaBigInt::decode(sequence)?;
            let z = RsaBigInt::decode(sequence)?;
            let c = RsaBigInt::decode(sequence)?;

            Ok(Self {id, group, label, xi, z, c})
        })
    }
}

impl PartialEq for Sh00SignatureShare {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.label == other.label && self.xi == other.xi && self.z == other.z && self.c == other.c && self.group.eq(&other.group)
    }
}

#[derive(Clone, AsnType, Serializable, Debug)]
pub struct Sh00SignedMessage {
    msg: Vec<u8>,
    sig: RsaBigInt
}

impl Sh00SignedMessage {
    pub fn get_sig(&self) -> RsaBigInt {
        self.sig.clone()
    }

    pub fn get_msg(&self) -> Vec<u8> {
        self.msg.clone()
    }
}

impl Encode for Sh00SignedMessage {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.msg.encode(sequence)?;
            self.sig.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Sh00SignedMessage {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let msg = Vec::<u8>::decode(sequence)?;
            let sig = RsaBigInt::decode(sequence)?;

            Ok(Self {msg, sig})
        })
    }
}

impl PartialEq for Sh00SignedMessage {
    fn eq(&self, other: &Self) -> bool {
        self.msg == other.msg && self.sig == other.sig
    }
}

#[derive(Clone, AsnType, Serializable, Debug)]
pub struct Sh00VerificationKey {
    v: RsaBigInt,
    vi: Vec<RsaBigInt>,
    u: RsaBigInt
}

impl Sh00VerificationKey {
    pub fn new(v: RsaBigInt,
        vi: Vec<RsaBigInt>,
        u: RsaBigInt) -> Self {
            Self{ v, vi, u}
        }
}

impl Encode for Sh00VerificationKey {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.v.encode(sequence)?;
            self.vi.encode(sequence)?;
            self.u.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Sh00VerificationKey {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let v = RsaBigInt::decode(sequence)?;
            let vi = Vec::<RsaBigInt>::decode(sequence)?;
            let u = RsaBigInt::decode(sequence)?;
            Ok(Self {v, vi, u})
        })
    }
}

impl PartialEq for Sh00VerificationKey {
    fn eq(&self, other: &Self) -> bool {
        self.v == other.v && self.vi == other.vi && self.u == other.u
    }
}

pub struct Sh00ThresholdSignature {
}


impl Sh00ThresholdSignature {
    pub fn verify(sig: &Sh00SignedMessage, pk: &Sh00PublicKey) -> bool {
        sig.sig.pow_mod(&pk.e, &pk.N).equals(&H1(&sig.msg, &pk.N, pk.modbits))
    }

    pub fn partial_sign(msg: &[u8], label: &[u8], sk: &Sh00PrivateKey, params: &mut ThresholdSignatureParams) -> Sh00SignatureShare {
        let N = sk.get_public_key().N.clone();
        let v = sk.get_public_key().verification_key.v.clone();
        let vi = sk.get_public_key().verification_key.vi[(sk.id - 1) as usize].clone();
        let si = sk.si.clone();

        let (x, _) = H(&msg, &sk.get_public_key()); 
        let xi = x.pow_mod(&si.add(&si), &N); // xi = x^(2*si)

        let x_hat = x.pow_mod(&BIGINT!(4), &N); // x_hat = x^4

        
        let bits = 2*sk.pubkey.modbits + 2 + 2*8;
        let r = RsaBigInt::new_rand(&mut params.rng, bits); // r = random in {0, 2^(2*modbits + 2 + 2*L1)}

        let v1 = v.pow_mod(&r, &N); //v1 = v^r
        let x1 = x_hat.pow_mod(&r, &N); // x1 = x_hat^r
        let xi2 = xi.pow(2).rmod(&N); //xi2 = xi^2

        let c = H2(&v, &x_hat, &vi, &xi2, &v1, &x1);

        let z = si.mul(&c).add(&r); // z = si*c + r

        return Sh00SignatureShare {id: sk.get_id(), group:sk.get_group(), label:label.to_vec(), xi:xi, z:z, c:c }
    }

    pub fn verify_share(share: &Sh00SignatureShare, msg: &[u8], pk: &Sh00PublicKey) -> bool {
        let N = pk.N.clone();
        let v = pk.verification_key.v.clone();
        let vi = pk.verification_key.vi[(share.id - 1) as usize].clone();
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

    pub fn assemble(shares: &Vec<Sh00SignatureShare>, msg: &[u8], pk: &Sh00PublicKey) -> Sh00SignedMessage {
        let u = pk.verification_key.u.clone();
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

fn H(m: &[u8], pk: &Sh00PublicKey) -> (RsaBigInt, isize) {
    let mut x = H1(m, &pk.N, pk.modbits);
    let j = RsaBigInt::jacobi(&x, &pk.N);
    if j == -1 {
        x = pk.verification_key.u.pow_mod(&pk.e, &pk.N).mul_mod(&x, &pk.N); // x = x * u^e
    } else if j == 0 {
        panic!("jacobi(x, n) == 0"); //TODO: make sure j != 0 by changing hash function H1
    }

    (x, j)
}

// TODO: improve hash function
fn H1(m: &[u8], n: &RsaBigInt, modbits:usize) -> RsaBigInt {
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
            hash.process_array(&[&g[..], &(i.to_le_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    RsaBigInt::from_bytes(&mut buf).rmod(&n)
}

fn H2(g1: &RsaBigInt, g2: &RsaBigInt, g3: &RsaBigInt, g4: &RsaBigInt, g5: &RsaBigInt, g6: &RsaBigInt) -> RsaBigInt {
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

    RsaBigInt::from_bytes(&mut buf)
}