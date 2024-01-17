#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use std::ops::BitAnd;

use asn1::{ParseError, WriteError};
use derive::DlShare;
use log::error;
use mcore::hash256::HASH256;
use rasn::AsnType;

use crate::dl_schemes::bigint::SizedBigInt;
use crate::interface::{DlShare, SchemeError, Serializable};
use crate::keys::keys::calc_key_id;
use crate::scheme_types_impl::GroupDetails;
use crate::{dl_schemes::common::interpolate, group::GroupElement, rand::RNG};
use theta_proto::scheme_types::{Group, ThresholdScheme};

pub struct Cks05ThresholdCoin {
    g: GroupElement,
}

#[derive(AsnType, Debug, Clone)]
pub struct Cks05PublicKey {
    id: String,
    group: Group,
    n: u16,
    k: u16,
    y: GroupElement,
    verification_key: Vec<GroupElement>,
}

impl Cks05PublicKey {
    pub fn get_key_id(&self) -> &str {
        &self.id
    }

    pub fn get_order(&self) -> SizedBigInt {
        self.y.get_order()
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
        group: &Group,
        n: usize,
        k: usize,
        y: &GroupElement,
        verification_key: &Vec<GroupElement>,
    ) -> Self {
        let mut k = Self {
            id: String::from(""),
            group: group.clone(),
            n: n as u16,
            k: k as u16,
            y: y.clone(),
            verification_key: verification_key.clone(),
        };

        let bytes = k.to_bytes().unwrap();
        let id = calc_key_id(&bytes);
        k.id = id;
        k
    }
}

impl Serializable for Cks05PublicKey {
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

                Ok(Self {
                    id: calc_key_id(bytes),
                    n,
                    k,
                    group,
                    y,
                    verification_key,
                })
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl PartialEq for Cks05PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.verification_key.eq(&other.verification_key) && self.y.eq(&other.y)
    }
}

#[derive(AsnType, Debug, Clone)]
pub struct Cks05PrivateKey {
    id: u16,
    xi: SizedBigInt,
    pubkey: Cks05PublicKey,
}

impl Cks05PrivateKey {
    pub fn new(id: u16, xi: &SizedBigInt, pubkey: &Cks05PublicKey) -> Self {
        Self {
            id,
            xi: xi.clone(),
            pubkey: pubkey.clone(),
        }
    }

    pub fn get_order(&self) -> SizedBigInt {
        self.pubkey.get_order()
    }

    pub fn get_share_id(&self) -> u16 {
        self.id
    }

    pub fn get_key_id(&self) -> &str {
        self.pubkey.get_key_id()
    }

    pub fn get_threshold(&self) -> u16 {
        self.pubkey.k
    }

    pub fn get_group(&self) -> &Group {
        self.pubkey.get_group()
    }

    pub fn get_public_key(&self) -> &Cks05PublicKey {
        &self.pubkey
    }
}

impl Serializable for Cks05PrivateKey {
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

                let b = d.read_element::<&[u8]>()?;
                let pubbytes = d.read_element::<&[u8]>()?;
                let res = Cks05PublicKey::from_bytes(&pubbytes.to_vec());
                if res.is_err() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault {}));
                }

                let pubkey = res.unwrap();

                let xi = SizedBigInt::from_bytes(&pubkey.get_group(), &b);

                return Ok(Self { id, xi, pubkey });
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl PartialEq for Cks05PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.xi == other.xi && self.pubkey == other.pubkey
    }
}

#[derive(AsnType, DlShare, Clone)]
pub struct Cks05CoinShare {
    id: u16,
    data: GroupElement,
    c: SizedBigInt,
    z: SizedBigInt,
}

impl Cks05CoinShare {
    pub fn get_scheme(&self) -> ThresholdScheme {
        ThresholdScheme::Cks05
    }
}

impl Serializable for Cks05CoinShare {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                w.write_element(&(self.get_group().clone() as i32))?;
                w.write_element(&self.data.to_bytes().as_slice())?;
                w.write_element(&self.c.to_bytes().as_slice())?;
                w.write_element(&self.z.to_bytes().as_slice())?;
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

                let bytes = d.read_element::<&[u8]>()?;
                let data = GroupElement::from_bytes(&bytes, &group, Option::None);

                let bytes = d.read_element::<&[u8]>()?;
                let c = SizedBigInt::from_bytes(&group, &bytes);

                let bytes = d.read_element::<&[u8]>()?;
                let z = SizedBigInt::from_bytes(&group, &bytes);

                return Ok(Self { id, data, c, z });
            });
        });

        if result.is_err() {
            error!("{}", result.err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl PartialEq for Cks05CoinShare {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.data.eq(&other.data)
            && self.c.eq(&other.c)
            && self.z.eq(&other.z)
    }
}

impl Cks05ThresholdCoin {
    pub fn create_share(name: &[u8], sk: &Cks05PrivateKey, rng: &mut RNG) -> Cks05CoinShare {
        let q = sk.get_order();

        let c_bar = H(name, &sk.get_group());
        let data = c_bar.pow(&sk.xi);

        let s = SizedBigInt::new_rand(&sk.get_group(), &q, rng);

        let h = GroupElement::new(&sk.get_group()).pow(&s);

        let h_bar = c_bar.pow(&s);

        let c = H1(
            &GroupElement::new(&sk.get_group()),
            &sk.pubkey.verification_key[(sk.id - 1) as usize],
            &h,
            &c_bar,
            &data,
            &h_bar,
        );

        let z = s.add(&SizedBigInt::rmul(&c, &sk.xi, &q)).rmod(&q);

        Cks05CoinShare {
            id: sk.id,
            data,
            c,
            z,
        }
    }

    pub fn verify_share(share: &Cks05CoinShare, name: &[u8], pk: &Cks05PublicKey) -> bool {
        let c_bar = H(name, &share.get_group());

        let h = GroupElement::new(&pk.group)
            .pow(&share.z)
            .div(&pk.verification_key[(share.id - 1) as usize].pow(&share.c));

        let h_bar = c_bar.pow(&share.z).div(&share.data.pow(&share.c));

        let c = H1(
            &GroupElement::new(&pk.group),
            &pk.verification_key[(share.id - 1) as usize],
            &h,
            &c_bar,
            &share.data,
            &h_bar,
        );

        share.c.equals(&c)
    }

    pub fn assemble(shares: &Vec<Cks05CoinShare>) -> u8 {
        let coin = interpolate(shares);
        H2(&coin)
    }
}

fn H(name: &[u8], group: &Group) -> GroupElement {
    let mut buf: Vec<u8> = Vec::new();
    let q = group.get_order();

    buf = [&buf[..], &name[..]].concat();

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

    let res = SizedBigInt::from_bytes(&group, &buf);
    res.rmod(&group.get_order());

    GroupElement::new_pow_big(&group, &res)
}

fn H1(
    g1: &GroupElement,
    g2: &GroupElement,
    g3: &GroupElement,
    g4: &GroupElement,
    g5: &GroupElement,
    g6: &GroupElement,
) -> SizedBigInt {
    let mut buf: Vec<u8> = Vec::new();
    let q = g1.get_order();

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

    let res = SizedBigInt::from_bytes(&g1.get_group(), &buf);
    res.rmod(&g1.get_order());

    res
}

// takes a group element and hashes it to a single bit
fn H2(g: &GroupElement) -> u8 {
    // generated 256-bit mask using https://catonmat.net/tools/generate-random-bits
    // TODO: use a verifiable way to generate this randomness
    const MASK: &[u8] = &[
        0b11011100, 0b01010111, 0b00100110, 0b01110100, 0b00100011, 0b00011101, 0b10101101,
        0b10010101, 0b11101001, 0b10011101, 0b00100100, 0b10000000, 0b01100001, 0b00011110,
        0b01011001, 0b00100110, 0b10111101, 0b01010100, 0b10011010, 0b00011000, 0b01111100,
        0b00000000, 0b10101101, 0b10011001, 0b10101011, 0b00111000, 0b11100111, 0b01000110,
        0b11010010, 0b10101010, 0b11110101, 0b01010110, 0b00111010, 0b11101001, 0b01011000,
        0b10011000, 0b11110010, 0b00000110, 0b10001100, 0b00000110, 0b10011101, 0b11001110,
        0b11010111, 0b01001101, 0b10000010, 0b11010010, 0b10110000, 0b01101111, 0b10101110,
        0b10111011, 0b10110001, 0b10101010, 0b11010010, 0b10011010, 0b00110111, 0b11001100,
        0b11011100, 0b11001111, 0b11110100, 0b00000001, 0b00000111, 0b11001010, 0b10101110,
        0b11100100, 0b10001001, 0b10011111, 0b00110100, 0b10101111, 0b11000111, 0b10000111,
        0b10001101, 0b00000001, 0b01011100, 0b11101101, 0b10111100, 0b11001000, 0b10000010,
        0b01110101, 0b10011111, 0b10010111, 0b01101010, 0b11011110, 0b10100101, 0b00110000,
        0b11010010, 0b01011110, 0b00111111, 0b01001010, 0b11011001, 0b01011010, 0b01010110,
        0b01001100, 0b10011000, 0b11100100, 0b00110100, 0b01100001, 0b00110110, 0b11000100,
        0b11110110, 0b11001011, 0b00101100, 0b11010001, 0b00110000, 0b11011010, 0b10011001,
        0b01101100, 0b10110110, 0b01110100, 0b11000000, 0b00101011, 0b00111101, 0b01111010,
        0b11100100, 0b10101101, 0b00010001, 0b00111000, 0b11000110, 0b00110110, 0b00110010,
        0b00010000, 0b00001100, 0b11001100, 0b11011111, 0b10100001, 0b01000001, 0b10010010,
        0b11101011, 0b11101001, 0b11101001, 0b00101111, 0b01001010, 0b11101110, 0b11001010,
        0b01100101, 0b10001100, 0b11101111, 0b11101100, 0b11101101, 0b10101111, 0b10000001,
        0b00001110, 0b00110001, 0b01101100, 0b00100001, 0b01111101, 0b11110011, 0b11110011,
        0b00011011, 0b00011001, 0b10000101, 0b01010110, 0b01001000, 0b11110000, 0b10011101,
        0b11000010, 0b01000001, 0b11001100, 0b11010101, 0b11010001, 0b10000110, 0b10000010,
        0b10000011, 0b10101101, 0b00110110, 0b10010001, 0b11110110, 0b10100110, 0b01000011,
        0b10010010, 0b10101110, 0b00001100, 0b00111001, 0b11110001, 0b10001001, 0b00000100,
        0b11100100, 0b11001000, 0b11000010, 0b11110101, 0b11010100, 0b00111010, 0b10011110,
        0b11000100, 0b11111001, 0b00000010, 0b00101111, 0b00111101, 0b10110011, 0b01001001,
        0b11001010, 0b00101011, 0b10100100, 0b00011110, 0b10011101, 0b01000010, 0b00010011,
        0b10111000, 0b11111111, 0b01110000, 0b10001010, 0b10010111, 0b01111111, 0b00111010,
        0b10110110, 0b00010101, 0b00110110, 0b11011110, 0b10001100, 0b11011000, 0b11011100,
        0b10110111, 0b01011101, 0b01001101, 0b00011110, 0b10011101, 0b01110110, 0b10011101,
        0b10001000, 0b10100000, 0b00101110, 0b11100101, 0b10101011, 0b11010011, 0b10101110,
        0b01000011, 0b11010101, 0b00100010, 0b00100010, 0b11111111, 0b11101101, 0b11011010,
        0b01001000, 0b00101011, 0b00010000, 0b01101101, 0b01001010, 0b11011010, 0b00110111,
        0b00001000, 0b01101100, 0b11110011, 0b11011100, 0b00001101, 0b00100010, 0b00111000,
        0b10001000, 0b01000101, 0b01111000, 0b01001100, 0b11001001, 0b10100101, 0b01100011,
        0b10111011, 0b01110011, 0b10010000, 0b01010110,
    ];

    let bytes = g.to_bytes();

    let mut bit: u8 = 0;

    // performing inner product of mask with bit representation of g
    for i in 0..bytes.len() {
        let g_byte = bytes[i];
        let mask_byte = MASK[i];

        bit ^= g_byte.bitand(mask_byte).count_ones() as u8 % 2;
    }

    bit
}
