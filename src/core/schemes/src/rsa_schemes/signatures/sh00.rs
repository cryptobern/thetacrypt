#![allow(non_snake_case)]

use crate::{
    integers::bigint::BigInt,
    interface::{SchemeError, Serializable, ThresholdScheme, ThresholdSignatureParams},
    keys::keys::calc_key_id,
    rsa_schemes::common::{ext_euclid, interpolate},
    BIGINT,
};
use asn1::{ParseError, WriteError};
use log::error;
use mcore::hash256::HASH256;
use theta_proto::scheme_types::Group;

#[derive(Clone, Debug)]
pub struct Sh00PublicKey {
    id: String,
    t: u16,
    n: u16,
    N: BigInt,
    e: BigInt,
    verification_key: Sh00VerificationKey,
    delta: usize,
    modbits: usize,
    group: Group,
}

fn mb2group(modbits: usize) -> Group {
    return match modbits {
        512 => Group::Rsa512,
        1024 => Group::Rsa1024,
        2048 => Group::Rsa2048,
        4096 => Group::Rsa4096,
        _ => panic!("invalid modbits value"),
    };
}

impl Sh00PublicKey {
    pub fn new(
        n: u16,
        t: u16,
        N: BigInt,
        e: BigInt,
        verification_key: Sh00VerificationKey,
        delta: usize,
        modbits: usize,
    ) -> Self {
        let group = mb2group(modbits);

        let mut k = Self {
            id: String::from(""),
            t,
            n,
            N,
            e,
            verification_key: verification_key,
            delta,
            modbits,
            group,
        };

        let bytes = k.to_bytes().unwrap();
        let id = calc_key_id(&bytes);
        k.id = id;
        k
    }

    pub fn get_key_id(&self) -> &str {
        &self.id
    }

    pub fn get_threshold(&self) -> u16 {
        return self.t;
    }

    pub fn get_n(&self) -> u16 {
        return self.n;
    }

    pub fn get_modbits(&self) -> usize {
        return self.modbits;
    }

    pub fn get_group(&self) -> &Group {
        &self.group
    }
}

impl Serializable for Sh00PublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.n as u64))?;
                w.write_element(&(self.t as u64))?;
                w.write_element(&self.N.to_bytes().as_slice())?;
                w.write_element(&self.e.to_bytes().as_slice())?;

                let bytes = self.verification_key.to_bytes();
                if bytes.is_err() {
                    return Err(WriteError::AllocationError);
                }

                w.write_element(&bytes.unwrap().as_slice())?;
                w.write_element(&(self.delta as u64))?;
                w.write_element(&(self.modbits as u64))?;
                Ok(())
            }))
        });

        if result.is_err() {
            return Err(SchemeError::SerializationFailed);
        }

        Ok(result.unwrap())
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let n = d.read_element::<u64>()? as u16;
                let t = d.read_element::<u64>()? as u16;

                let mut b = d.read_element::<&[u8]>()?;
                let N = BigInt::from_bytes(&mut b);

                b = d.read_element::<&[u8]>()?;
                let e = BigInt::from_bytes(&mut b);

                let verify_bytes = d.read_element::<&[u8]>()?;
                let res = Sh00VerificationKey::from_bytes(&verify_bytes.to_vec());
                if res.is_err() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault {}));
                }

                let verification_key = res.unwrap();

                let delta = d.read_element::<u64>()? as usize;
                let modbits = d.read_element::<u64>()? as usize;

                let group = mb2group(modbits);

                return Ok(Self {
                    id: calc_key_id(bytes),
                    n,
                    t,
                    N,
                    e,
                    verification_key,
                    delta,
                    modbits,
                    group,
                });
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl PartialEq for Sh00PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.N.equals(&other.N)
            && self.e.equals(&other.e)
            && self.verification_key.eq(&other.verification_key)
            && self.delta == other.delta
            && self.modbits == other.modbits
    }
}

#[derive(Clone, Debug)]
pub struct Sh00PrivateKey {
    id: u16,
    m: BigInt,
    si: BigInt,
    pubkey: Sh00PublicKey,
}

impl Sh00PrivateKey {
    pub fn new(id: u16, m: &BigInt, si: &BigInt, pubkey: &Sh00PublicKey) -> Self {
        Self {
            id,
            m: m.clone(),
            si: si.clone(),
            pubkey: pubkey.clone(),
        }
    }

    pub fn get_public_key(&self) -> &Sh00PublicKey {
        &self.pubkey
    }

    pub fn get_share_id(&self) -> u16 {
        self.id
    }

    pub fn get_key_id(&self) -> &str {
        self.pubkey.get_key_id()
    }

    pub fn get_threshold(&self) -> u16 {
        self.pubkey.get_threshold()
    }

    pub fn get_group(&self) -> &Group {
        self.pubkey.get_group()
    }
}

impl Serializable for Sh00PrivateKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                w.write_element(&self.m.to_bytes().as_slice())?;
                w.write_element(&self.si.to_bytes().as_slice())?;

                let bytes = self.pubkey.to_bytes();
                if bytes.is_err() {
                    return Err(WriteError::AllocationError);
                }

                w.write_element(&bytes.unwrap().as_slice())?;
                Ok(())
            }))
        });

        if result.is_err() {
            return Err(SchemeError::SerializationFailed);
        }

        Ok(result.unwrap())
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let id = d.read_element::<u64>()? as u16;
                let mbytes = d.read_element::<&[u8]>()?;
                let sibytes = d.read_element::<&[u8]>()?;
                let pubbytes = d.read_element::<&[u8]>()?;
                let res = Sh00PublicKey::from_bytes(&pubbytes.to_vec());
                if res.is_err() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault {}));
                }

                let pubkey = res.unwrap();

                let m = BigInt::from_bytes(mbytes);
                let si = BigInt::from_bytes(sibytes);

                return Ok(Self { id, m, si, pubkey });
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl PartialEq for Sh00PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.m.equals(&other.m)
            && self.si.equals(&other.si)
            && self.pubkey.eq(&other.pubkey)
    }
}

#[derive(Clone, Debug)]
pub struct Sh00SignatureShare {
    group: Group,
    id: u16,
    label: Vec<u8>,
    xi: BigInt,
    z: BigInt,
    c: BigInt,
}

impl Sh00SignatureShare {
    pub fn get_id(&self) -> u16 {
        self.id
    }

    pub fn get_data(&self) -> &BigInt {
        &self.xi
    }

    pub fn get_label(&self) -> &[u8] {
        &self.label
    }

    pub fn get_group(&self) -> &Group {
        &self.group
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        ThresholdScheme::Sh00
    }
}

impl Serializable for Sh00SignatureShare {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                w.write_element(&(self.group as i32))?;
                w.write_element(&self.label.as_slice())?;
                w.write_element(&self.xi.to_bytes().as_slice())?;
                w.write_element(&self.z.to_bytes().as_slice())?;
                w.write_element(&self.c.to_bytes().as_slice())?;
                Ok(())
            }))
        });

        if result.is_err() {
            return Err(SchemeError::SerializationFailed);
        }

        Ok(result.unwrap())
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let id = d.read_element::<u64>()? as u16;
                let g = Group::from_i32(d.read_element::<i32>()?);
                if g.is_none() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault));
                }
                let group = g.unwrap();
                let label = d.read_element::<&[u8]>()?;

                let bytes = d.read_element::<&[u8]>()?;
                let xi = BigInt::from_bytes(&bytes);

                let bytes = d.read_element::<&[u8]>()?;
                let z = BigInt::from_bytes(&bytes);

                let bytes = d.read_element::<&[u8]>()?;
                let c = BigInt::from_bytes(&bytes);

                return Ok(Self {
                    id,
                    group,
                    label: label.to_vec(),
                    xi,
                    z,
                    c,
                });
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl PartialEq for Sh00SignatureShare {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.label == other.label
            && self.xi == other.xi
            && self.z == other.z
            && self.c == other.c
            && self.group.eq(&other.group)
    }
}

#[derive(Clone, Debug)]
pub struct Sh00Signature {
    sig: BigInt,
}

impl Sh00Signature {
    pub fn get_sig(&self) -> BigInt {
        self.sig.clone()
    }
}

impl Serializable for Sh00Signature {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&self.sig.to_bytes().as_slice())?;
                Ok(())
            }))
        });

        if result.is_err() {
            return Err(SchemeError::SerializationFailed);
        }

        Ok(result.unwrap())
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let bytes = d.read_element::<&[u8]>()?;
                let sig = BigInt::from_bytes(&bytes);

                return Ok(Self { sig });
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl PartialEq for Sh00Signature {
    fn eq(&self, other: &Self) -> bool {
        self.sig == other.sig
    }
}

#[derive(Clone, Debug)]
pub struct Sh00VerificationKey {
    v: BigInt,
    vi: Vec<BigInt>,
    u: BigInt,
}

impl Sh00VerificationKey {
    pub fn new(v: BigInt, vi: Vec<BigInt>, u: BigInt) -> Self {
        Self { v, vi, u }
    }
}

impl Serializable for Sh00VerificationKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&self.v.to_bytes().as_slice())?;
                w.write_element(&(self.vi.len() as u64))?;

                for i in 0..self.vi.len() {
                    w.write_element(&self.vi[i].to_bytes().as_slice())?;
                }

                w.write_element(&self.u.to_bytes().as_slice())?;
                Ok(())
            }))
        });

        if result.is_err() {
            return Err(SchemeError::SerializationFailed);
        }

        Ok(result.unwrap())
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let mut bytes = d.read_element::<&[u8]>()?;
                let v = BigInt::from_bytes(&mut bytes);
                let len = d.read_element::<u64>()? as u16;

                let mut vi = Vec::new();
                for _ in 0..len {
                    let mut bytes = d.read_element::<&[u8]>()?;
                    let el = BigInt::from_bytes(&mut bytes);
                    vi.push(el);
                }

                let mut bytes = d.read_element::<&[u8]>()?;
                let u = BigInt::from_bytes(&mut bytes);

                return Ok(Self { v, vi, u });
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl PartialEq for Sh00VerificationKey {
    fn eq(&self, other: &Self) -> bool {
        self.v == other.v && self.vi == other.vi && self.u == other.u
    }
}

pub struct Sh00ThresholdSignature {}

impl Sh00ThresholdSignature {
    pub fn verify(sig: &Sh00Signature, pk: &Sh00PublicKey, msg: &[u8]) -> bool {
        sig.sig
            .pow_mod(&pk.e, &pk.N)
            .equals(&H1(&msg, &pk.N, pk.modbits))
    }

    pub fn partial_sign(
        msg: &[u8],
        label: &[u8],
        sk: &Sh00PrivateKey,
        params: &mut ThresholdSignatureParams,
    ) -> Sh00SignatureShare {
        let N = sk.get_public_key().N.clone();
        let v = sk.get_public_key().verification_key.v.clone();
        let vi = sk.get_public_key().verification_key.vi[(sk.id - 1) as usize].clone();
        let si = sk.si.clone();

        let (x, _) = H(&msg, &sk.get_public_key());
        let xi = x.pow_mod(&si.add(&si), &N); // xi = x^(2*si)

        let x_hat = x.pow_mod(&BIGINT!(4), &N); // x_hat = x^4

        let bits = 2 * sk.pubkey.modbits + 2 + 2 * 8;
        let r = BigInt::new_rand(&mut params.rng, bits); // r = random in {0, 2^(2*modbits + 2 + 2*L1)}

        let v1 = v.pow_mod(&r, &N); //v1 = v^r
        let x1 = x_hat.pow_mod(&r, &N); // x1 = x_hat^r
        let xi2 = xi.pow(2).rmod(&N); //xi2 = xi^2

        let c = H2(&v, &x_hat, &vi, &xi2, &v1, &x1);

        let z = si.mul(&c).add(&r); // z = si*c + r

        return Sh00SignatureShare {
            id: sk.get_share_id(),
            group: sk.get_group().clone(),
            label: label.to_vec(),
            xi: xi,
            z: z,
            c: c,
        };
    }

    pub fn verify_share(share: &Sh00SignatureShare, msg: &[u8], pk: &Sh00PublicKey) -> bool {
        let N = pk.N.clone();
        let v = pk.verification_key.v.clone();
        let vi = pk.verification_key.vi[(share.id - 1) as usize].clone();
        let (x, _) = H(&msg, &pk);
        let z = share.z.clone();
        let c = share.c.clone();
        let xi = share.get_data();

        let x_hat = x.pow_mod(&BIGINT!(4), &N); // x_hat = x^4

        let xi2 = share.xi.pow(2).rmod(&N); //xi2 = xi^2

        let div = vi.pow_mod(&c, &N).inv_mod(&N);
        let v1 = v.pow_mod(&z, &N).mul_mod(&div, &N); // v1 = v^z / vi^c

        let div = xi.pow_mod(&c.add(&c), &N).inv_mod(&N);
        let x1 = x_hat.pow_mod(&z, &N).mul_mod(&div, &N); // x1 = x_hat^z / xi^(2c)

        let c2 = H2(&v, &x_hat, &vi, &xi2, &v1, &x1);

        c2.equals(&c)
    }

    pub fn assemble(
        shares: &Vec<Sh00SignatureShare>,
        msg: &[u8],
        pk: &Sh00PublicKey,
    ) -> Sh00Signature {
        let u = pk.verification_key.u.clone();
        let N = pk.N.clone();

        let (a, b) = ext_euclid(&BIGINT!(4), &pk.e); // 4*a + e*b = 1
        let (x, j) = H(&msg, &pk);
        let w = interpolate(&shares, &pk.N, pk.delta).pow_mod(&a, &N);
        let mut y = w.mul_mod(&x.pow_mod(&b, &pk.N), &pk.N); // y = w^a * x^b

        if j == -1 {
            y = u.inv_mod(&pk.N).mul_mod(&y, &N);
        }

        Sh00Signature { sig: y }
    }
}

fn H(m: &[u8], pk: &Sh00PublicKey) -> (BigInt, isize) {
    let mut x = H1(m, &pk.N, pk.modbits);
    let j = BigInt::jacobi(&x, &pk.N);
    if j == -1 {
        x = pk
            .verification_key
            .u
            .pow_mod(&pk.e, &pk.N)
            .mul_mod(&x, &pk.N); // x = x * u^e
    } else if j == 0 {
        panic!("jacobi(x, n) == 0"); //TODO: make sure j != 0 by changing hash function H1
    }

    (x, j as isize)
}

// TODO: improve hash function
fn H1(m: &[u8], n: &BigInt, modbits: usize) -> BigInt {
    let mut hash = HASH256::new();
    hash.process_array(&m);
    let h = hash.hash();

    let mut buf = Vec::new();
    buf = [&buf[..], &h].concat();

    let blen = buf.len() * 4;
    let max = (((modbits - blen) / buf.len()) as f64).ceil() as isize;

    if modbits > blen {
        let mut g: [u8; 32];
        for i in 1..max {
            g = h.clone();
            hash.process_array(&[&g[..], &(i.to_le_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    BigInt::from_bytes(&mut buf).rmod(&n)
}

fn H2(g1: &BigInt, g2: &BigInt, g3: &BigInt, g4: &BigInt, g5: &BigInt, g6: &BigInt) -> BigInt {
    let mut buf: Vec<u8> = Vec::new();

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
