use crate::interface::Serializable;
use crate::keys::keys::calc_key_id;
use crate::{
    interface::{SchemeError, ThresholdScheme},
    scheme_types_impl::GroupDetails,
};
use asn1::{ParseError, WriteError};
use chacha20poly1305::{
    aead::{Aead, NewAead},
    ChaCha20Poly1305, Key, Nonce,
};
use mcore::hash256::HASH256;
use rasn::{AsnType, Decode, Encode, Encoder};
use theta_derive::DlShare;
use theta_proto::scheme_types::Group;

use crate::groups::group::GroupElement;
use crate::integers::sizedint::SizedBigInt;
use crate::{
    dl_schemes::common::{gen_symm_key, interpolate, xor},
    interface::{DlShare, ThresholdCipherParams},
    rand::RNG,
};
pub struct Sg02ThresholdCipher {}

#[derive(Clone, Debug, PartialEq)]
pub struct Sg02PublicKey {
    n: u16,
    k: u16,
    group: Group,
    y: GroupElement,
    verification_key: Vec<GroupElement>,
    g_bar: GroupElement,
    id: String,
}

impl Sg02PublicKey {
    pub fn get_order(&self) -> SizedBigInt {
        self.y.get_order()
    }

    pub fn get_key_id(&self) -> &str {
        &self.id
    }

    pub fn get_group(&self) -> &Group {
        &self.group
    }

    pub fn get_threshold(&self) -> u16 {
        self.k
    }

    pub fn get_n(&self) -> u16 {
        self.n
    }

    pub fn new(
        n: usize,
        k: usize,
        group: &Group,
        y: &GroupElement,
        verification_key: &Vec<GroupElement>,
        g_bar: &GroupElement,
    ) -> Self {
        if !y.is_type(&group) || !verification_key[0].is_type(&group) || !g_bar.is_type(&group) {
            panic!("incompatible groups");
        }
        let mut k = Self {
            id: String::from(""),
            n: n as u16,
            k: k as u16,
            group: group.clone(),
            y: y.clone(),
            verification_key: verification_key.clone(),
            g_bar: g_bar.clone(),
        };

        let bytes = k.to_bytes().unwrap();
        let id = calc_key_id(&bytes);
        k.id = id;
        k
    }
}

impl Serializable for Sg02PublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(*self.get_group() as i32))?;
                w.write_element(&(self.n as u64))?;
                w.write_element(&(self.k as u64))?;
                w.write_element(&self.y.to_bytes().as_slice())?;

                for i in 0..self.verification_key.len() {
                    w.write_element(&self.verification_key[i].to_bytes().as_slice())?;
                }

                w.write_element(&self.g_bar.to_bytes().as_slice())?;
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
                let g = Group::from_i32(d.read_element::<i32>()?);
                if g.is_none() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault));
                }
                let group = g.unwrap();
                let n = d.read_element::<u64>()? as u16;
                let k = d.read_element::<u64>()? as u16;

                let mut b = d.read_element::<&[u8]>()?;
                let y = GroupElement::from_bytes(&b, &group, Option::None);

                let mut verification_key = Vec::new();

                for _i in 0..n {
                    b = d.read_element::<&[u8]>()?;
                    verification_key.push(GroupElement::from_bytes(&b, &group, Option::None));
                }

                b = d.read_element::<&[u8]>()?;
                let g_bar = GroupElement::from_bytes(&b, &group, Option::None);

                Ok(Self {
                    id: calc_key_id(bytes),
                    n,
                    k,
                    group,
                    y,
                    verification_key,
                    g_bar,
                })
            });
        });

        if result.is_err() {
            println!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Sg02PrivateKey {
    id: u16,
    xi: SizedBigInt,
    pubkey: Sg02PublicKey,
}

impl Sg02PrivateKey {
    pub fn get_order(&self) -> SizedBigInt {
        self.pubkey.get_order()
    }

    pub fn get_share_id(&self) -> u16 {
        self.id
    }

    pub fn get_key_id(&self) -> &str {
        &self.pubkey.id
    }

    pub fn get_threshold(&self) -> u16 {
        self.pubkey.k
    }

    pub fn get_group(&self) -> &Group {
        self.pubkey.get_group()
    }

    pub fn new(id: u16, xi: &SizedBigInt, pubkey: &Sg02PublicKey) -> Self {
        Self {
            id: id.clone(),
            xi: xi.clone(),
            pubkey: pubkey.clone(),
        }
    }

    pub fn get_public_key(&self) -> &Sg02PublicKey {
        &self.pubkey
    }
}

impl Serializable for Sg02PrivateKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                w.write_element(&self.xi.to_bytes().as_slice())?;

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
                let bytes = d.read_element::<&[u8]>()?;
                let pubbytes = d.read_element::<&[u8]>()?;
                let res = Sg02PublicKey::from_bytes(&pubbytes.to_vec());
                if res.is_err() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault {}));
                }

                let pubkey = res.unwrap();

                let xi = SizedBigInt::from_bytes(&pubkey.get_group(), &bytes);

                return Ok(Self { id, xi, pubkey });
            });
        });

        if result.is_err() {
            println!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Sg02Ciphertext {
    label: Vec<u8>,
    ctxt: Vec<u8>,
    u: GroupElement,
    u_bar: GroupElement,
    e: SizedBigInt,
    f: SizedBigInt,
    c_k: Vec<u8>,
    key_id: String,
}

impl Serializable for Sg02Ciphertext {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.get_group().clone() as i32))?;
                w.write_element(&self.label.as_slice())?;
                w.write_element(&self.ctxt.as_slice())?;
                w.write_element(&self.u.to_bytes().as_slice())?;
                w.write_element(&self.u_bar.to_bytes().as_slice())?;
                w.write_element(&self.e.to_bytes().as_slice())?;
                w.write_element(&self.f.to_bytes().as_slice())?;
                w.write_element(&self.c_k.as_slice())?;
                w.write_element(&self.key_id.as_bytes())?;
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
                let g = Group::from_i32(d.read_element::<i32>()?);
                if g.is_none() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault));
                }
                let group = g.unwrap();
                let label = d.read_element::<&[u8]>()?.to_vec();
                let msg = d.read_element::<&[u8]>()?.to_vec();

                let bytes = d.read_element::<&[u8]>()?;
                let u = GroupElement::from_bytes(&bytes, &group, Option::None);

                let bytes = d.read_element::<&[u8]>()?;
                let u_bar = GroupElement::from_bytes(&bytes, &group, Option::None);

                let bytes = d.read_element::<&[u8]>()?;
                let e = SizedBigInt::from_bytes(&group, &bytes);

                let bytes = d.read_element::<&[u8]>()?;
                let f = SizedBigInt::from_bytes(&group, &bytes);

                let c_k = d.read_element::<&[u8]>()?.to_vec();
                let key_id = String::from_utf8(d.read_element::<&[u8]>()?.to_vec());

                if key_id.is_err() {
                    return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                }

                let key_id = key_id.unwrap();

                return Ok(Sg02Ciphertext {
                    label,
                    ctxt: msg,
                    u,
                    u_bar,
                    e,
                    f,
                    c_k,
                    key_id,
                });
            });
        });

        if result.is_err() {
            println!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl Sg02Ciphertext {
    pub fn new(
        label: Vec<u8>,
        ctxt: Vec<u8>,
        u: GroupElement,
        u_bar: GroupElement,
        e: SizedBigInt,
        f: SizedBigInt,
        c_k: Vec<u8>,
        key_id: String,
    ) -> Self {
        Self {
            ctxt,
            label,
            u,
            u_bar,
            e,
            f,
            c_k,
            key_id,
        }
    }
    pub fn get_ctxt(&self) -> &[u8] {
        &self.ctxt
    }
    pub fn get_ck(&self) -> &[u8] {
        &self.c_k
    }
    pub fn get_label(&self) -> &[u8] {
        &self.label
    }
    pub fn get_scheme(&self) -> ThresholdScheme {
        ThresholdScheme::Sg02
    }
    pub fn get_group(&self) -> &Group {
        self.e.get_group()
    }
    pub fn get_key_id(&self) -> &str {
        &self.key_id
    }
}

#[derive(Clone, PartialEq, DlShare)]
pub struct Sg02DecryptionShare {
    id: u16,
    label: Vec<u8>,
    data: GroupElement,
    ei: SizedBigInt,
    fi: SizedBigInt,
}

impl Sg02DecryptionShare {
    pub fn get_label(&self) -> &[u8] {
        &self.label
    }
    pub fn get_scheme(&self) -> ThresholdScheme {
        ThresholdScheme::Sg02
    }
}

impl Serializable for Sg02DecryptionShare {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                w.write_element(&(self.get_group().clone() as i32))?;
                w.write_element(&self.label.as_slice())?;
                w.write_element(&self.data.to_bytes().as_slice())?;
                w.write_element(&self.ei.to_bytes().as_slice())?;
                w.write_element(&self.fi.to_bytes().as_slice())?;
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
                let label = d.read_element::<&[u8]>()?.to_vec();

                let bytes = d.read_element::<&[u8]>()?;
                let data = GroupElement::from_bytes(&bytes, &group, Option::None);

                let bytes = d.read_element::<&[u8]>()?;
                let ei = SizedBigInt::from_bytes(&group, &bytes);

                let bytes = d.read_element::<&[u8]>()?;
                let fi = SizedBigInt::from_bytes(&group, &bytes);

                return Ok(Self {
                    id,
                    label,
                    data,
                    ei,
                    fi,
                });
            });
        });

        if result.is_err() {
            println!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl Sg02ThresholdCipher {
    pub fn encrypt(
        msg: &[u8],
        label: &[u8],
        pk: &Sg02PublicKey,
        params: &mut ThresholdCipherParams,
    ) -> Sg02Ciphertext {
        let group = pk.get_group();
        let order = group.get_order();
        let rng = &mut params.rng;

        let r = SizedBigInt::new_rand(&group, &order, rng);
        let u = GroupElement::new_pow_big(&group, &r);
        let ry = pk.y.pow(&r);

        let k = gen_symm_key(rng);
        let key = Key::from_slice(&k);
        let cipher = ChaCha20Poly1305::new(key);
        let encryption: Vec<u8> = cipher
            .encrypt(Nonce::from_slice(&ry.to_bytes()[0..12]), msg)
            .expect("Failed to encrypt plaintext");

        let c_k = xor(h(&ry), (k).to_vec());

        let s = SizedBigInt::new_rand(&group, &order, rng);
        let w = GroupElement::new_pow_big(&group, &s);

        let w_bar = pk.g_bar.pow(&s);
        let u_bar = pk.g_bar.pow(&r);

        let e = h1(&c_k, &label, &u, &w, &u_bar, &w_bar);

        let f = s.add(&SizedBigInt::rmul(&e, &r, &order)).rmod(&order);

        let c = Sg02Ciphertext {
            label: label.to_vec(),
            ctxt: encryption,
            c_k: c_k.to_vec(),
            u: u,
            u_bar: u_bar,
            e: e,
            f: f,
            key_id: pk.id.clone(),
        };
        c
    }

    pub fn verify_ciphertext(ct: &Sg02Ciphertext, pk: &Sg02PublicKey) -> bool {
        let w = GroupElement::new_pow_big(&pk.group, &ct.f).div(&ct.u.pow(&ct.e));

        let w_bar = pk.g_bar.pow(&ct.f).div(&ct.u_bar.pow(&ct.e));

        let e2 = h1(&ct.c_k, &ct.label, &ct.u, &w, &ct.u_bar, &w_bar);
        ct.e.equals(&e2)
    }

    pub fn partial_decrypt(
        ct: &Sg02Ciphertext,
        sk: &Sg02PrivateKey,
        params: &mut ThresholdCipherParams,
    ) -> Sg02DecryptionShare {
        let group = sk.get_group();
        let order = group.get_order();

        let data = ct.u.pow(&sk.xi);
        let si = SizedBigInt::new_rand(&group, &order, &mut params.rng);

        let ui_bar = ct.u.pow(&si);
        let hi_bar = GroupElement::new(&group).pow(&si);

        let ei = h2(&data, &ui_bar, &hi_bar);
        let fi = si.add(&SizedBigInt::rmul(&sk.xi, &ei, &order)).rmod(&order);

        Sg02DecryptionShare {
            id: sk.id.clone(),
            data: data,
            label: ct.label.clone(),
            ei: ei,
            fi: fi,
        }
    }

    pub fn verify_share(
        share: &Sg02DecryptionShare,
        ct: &Sg02Ciphertext,
        pk: &Sg02PublicKey,
    ) -> bool {
        let ui_bar = ct.u.pow(&share.fi).div(&share.data.pow(&share.ei));

        let hi_bar = GroupElement::new(&pk.group)
            .pow(&share.fi)
            .div(&pk.verification_key[(share.id - 1) as usize].pow(&share.ei));

        let ei2 = h2(&share.data, &ui_bar, &hi_bar);

        share.ei.equals(&ei2)
    }

    pub fn assemble(
        shares: &Vec<Sg02DecryptionShare>,
        ct: &Sg02Ciphertext,
    ) -> Result<Vec<u8>, SchemeError> {
        let ry = interpolate(shares);
        let k = xor(h(&ry), ct.c_k.clone());
        let key = Key::from_slice(&k);
        let cipher = ChaCha20Poly1305::new(key);
        let msg = cipher.decrypt(Nonce::from_slice(&ry.to_bytes()[0..12]), ct.ctxt.as_ref());

        if msg.is_err() {
            return Err(SchemeError::MacFailure);
        }

        Ok(msg.unwrap())
    }
}

// hash ECP to bit string
fn h(x: &GroupElement) -> Vec<u8> {
    let mut h = HASH256::new();
    let buf = x.to_bytes();

    h.process_array(&buf);

    let r = h.hash().to_vec();
    r
}

fn h1(
    m1: &[u8],
    m2: &[u8],
    g1: &GroupElement,
    g2: &GroupElement,
    g3: &GroupElement,
    g4: &GroupElement,
) -> SizedBigInt {
    let mut buf: Vec<u8> = Vec::new();
    let q = g1.get_order();

    buf = [&buf[..], &m1[..]].concat();
    buf = [&buf[..], &m2[..]].concat();
    buf = [&buf[..], &g1.to_bytes()[..]].concat();
    buf = [&buf[..], &g2.to_bytes()[..]].concat();
    buf = [&buf[..], &g3.to_bytes()[..]].concat();
    buf = [&buf[..], &g4.to_bytes()[..]].concat();

    let mut hash = HASH256::new();
    hash.process_array(&buf);
    let h = hash.hash();

    buf = Vec::new();
    buf = [&buf[..], &h].concat();

    let nbits = q.nbytes() * 8;

    if nbits > buf.len() * 4 {
        let mut g: [u8; 32];
        for i in 1..(((nbits - buf.len() * 4) / buf.len() * 8) as f64).ceil() as isize {
            g = h.clone();
            hash.process_array(&[&g[..], &(i.to_le_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    SizedBigInt::from_bytes(&g1.get_group(), &buf).rmod(&g1.get_order())
}

fn h2(g1: &GroupElement, g2: &GroupElement, g3: &GroupElement) -> SizedBigInt {
    let mut buf: Vec<u8> = Vec::new();
    let q = g1.get_order();

    buf = [&buf[..], &g1.to_bytes()[..]].concat();
    buf = [&buf[..], &g2.to_bytes()[..]].concat();
    buf = [&buf[..], &g3.to_bytes()[..]].concat();

    let mut hash = HASH256::new();
    hash.process_array(&buf);
    let h = hash.hash();

    buf = Vec::new();
    buf = [&buf[..], &h].concat();

    let nbits = q.nbytes() * 8;

    if nbits > buf.len() * 4 {
        let mut g: [u8; 32];
        for i in 1..(((nbits - buf.len() * 4) / buf.len() * 8) as f64).ceil() as isize {
            g = h.clone();
            hash.process_array(&[&g[..], &(i.to_le_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    SizedBigInt::from_bytes(&g1.get_group(), &buf).rmod(&g1.get_order())
}
