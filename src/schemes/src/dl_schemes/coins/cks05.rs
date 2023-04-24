#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use asn1::{WriteError, ParseError};
use derive::{DlShare};
use mcore::{hash256::HASH256};
use rasn::{AsnType, Encode, Decode};

use crate::interface::{DlShare, Serializable, ThresholdCryptoError};
use crate::{group::GroupElement, dl_schemes::{common::interpolate}, rand::RNG};
use crate::interface::ThresholdScheme;
use  crate::group::Group;
use crate::dl_schemes::bigint::BigImpl;

pub struct Cks05ThresholdCoin {
    g: GroupElement,
}

#[derive(AsnType, Debug, Clone)]
pub struct Cks05PublicKey {
    group: Group,
    n: u16,
    k: u16,
    y: GroupElement,
    verification_key: Vec<GroupElement>
}

impl Cks05PublicKey {
    pub fn get_order(&self) -> BigImpl {
        self.y.get_order()
    }

    pub fn get_group(&self) -> Group {
        self.group.clone()
    }

    pub fn get_threshold(&self) -> u16 {
        self.k
    }

    pub fn get_n(&self) -> u16  {
        self.n
    }

    pub fn new(group:&Group, n:usize, k:usize, y: &GroupElement, verification_key: &Vec<GroupElement>) -> Self {
        Self {
            group:group.clone(),
            n:n as u16,
            k:k as u16,
            y: y.clone(),
            verification_key: verification_key.clone()
        }
    }
}

impl Serializable for Cks05PublicKey {
    fn serialize(&self) -> Result<Vec<u8>, ThresholdCryptoError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&self.get_group().get_code())?;
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
            return Err(ThresholdCryptoError::SerializationFailed);
        }

        Ok(result.unwrap())
    }

    fn deserialize(bytes: &Vec<u8>) -> Result<Self, ThresholdCryptoError>  {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let g = Group::from_code(d.read_element::<u8>()?);
                if g.is_err() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault));
                }
                let group = g.unwrap();
                let n = d.read_element::<u64>()? as u16;
                let k = d.read_element::<u64>()? as u16;
                
                let bytes = d.read_element::<&[u8]>()?;
                let y = GroupElement::from_bytes(&bytes, &group, Option::None);
                
                let mut verification_key = Vec::new();

                for _i in 0..n {
                    let bytes = d.read_element::<&[u8]>()?;
                    verification_key.push(GroupElement::from_bytes(&bytes, &group, Option::None));
                }

                Ok(Self{n, k, group, y, verification_key})
            })
        });

        if result.is_err() {
            println!("{}", result.err().unwrap().to_string());
            return Err(ThresholdCryptoError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl PartialEq for Cks05PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.verification_key.eq(&other.verification_key) &&  self.y.eq(&other.y) 
    }
}

#[derive(AsnType, Debug, Clone)]
pub struct Cks05PrivateKey {
    id: u16,
    xi: BigImpl,
    pubkey: Cks05PublicKey,
}

impl Cks05PrivateKey {
    pub fn new(id: u16, xi: &BigImpl, pubkey: &Cks05PublicKey) -> Self {
        Self {
            id,
            xi: xi.clone(),
            pubkey: pubkey.clone(),
        }
    }

    pub fn get_order(&self) -> BigImpl {
        self.pubkey.get_order()
    }

    pub fn get_id(&self) -> u16 {
        self.id
    }

    pub fn get_threshold(&self) -> u16 {
        self.pubkey.k
    }

    pub fn get_group(&self) -> Group {
        self.pubkey.get_group()
    }

    pub fn get_public_key(&self) -> Cks05PublicKey {
        self.pubkey.clone()
    }
}

impl Serializable for Cks05PrivateKey {
    fn serialize(&self) -> Result<Vec<u8>, ThresholdCryptoError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                w.write_element(&self.xi.to_bytes().as_slice())?;

                let bytes = self.pubkey.serialize();
                if bytes.is_err() {
                    return Err(WriteError::AllocationError);
                }

                w.write_element(&bytes.unwrap().as_slice())?;
                Ok(())
            }))
        });

        if result.is_err() {
            return Err(ThresholdCryptoError::SerializationFailed);
        }

        Ok(result.unwrap())
    }

    fn deserialize(bytes: &Vec<u8>) -> Result<Self, ThresholdCryptoError>  {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let id = d.read_element::<u64>()? as u16;

                let bytes = d.read_element::<&[u8]>()?;
                let pubbytes = d.read_element::<&[u8]>()?;
                let res = Cks05PublicKey::deserialize(&pubbytes.to_vec());
                if res.is_err() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault { }));
                }

                let pubkey = res.unwrap();

                let xi = BigImpl::from_bytes(&pubkey.get_group(), &bytes);

                return Ok(Self {id, xi, pubkey});
            })
        });

        if result.is_err() {
            println!("{}", result.err().unwrap().to_string());
            return Err(ThresholdCryptoError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl PartialEq for Cks05PrivateKey{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.xi == other.xi && self.pubkey == other.pubkey
    }
}

#[derive(AsnType, DlShare, Clone)]
pub struct Cks05CoinShare {
    id: u16,
    data: GroupElement,
    c: BigImpl,
    z: BigImpl,
}

impl Cks05CoinShare {
    pub fn get_scheme(&self) -> ThresholdScheme { ThresholdScheme::Cks05 }
}

impl Serializable for Cks05CoinShare {
    fn serialize(&self) -> Result<Vec<u8>, ThresholdCryptoError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                w.write_element(&self.get_group().get_code())?;
                w.write_element(&self.data.to_bytes().as_slice())?;
                w.write_element(&self.c.to_bytes().as_slice())?;
                w.write_element(&self.z.to_bytes().as_slice())?;
                Ok(())
            }))
        });

        if result.is_err() {
            return Err(ThresholdCryptoError::SerializationFailed);
        }

        Ok(result.unwrap())
    }

    fn deserialize(bytes: &Vec<u8>) -> Result<Self, ThresholdCryptoError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let id = d.read_element::<u64>()? as u16;
                let g = Group::from_code(d.read_element::<u8>()?);
                if g.is_err() {
                    return Err(ParseError::new(asn1::ParseErrorKind::EncodedDefault));
                }
                let group = g.unwrap();
                
                let bytes = d.read_element::<&[u8]>()?;
                let data = GroupElement::from_bytes(&bytes, &group, Option::None);

                let bytes = d.read_element::<&[u8]>()?;
                let c = BigImpl::from_bytes(&group, &bytes);

                let bytes = d.read_element::<&[u8]>()?;
                let z = BigImpl::from_bytes(&group, &bytes);

                return Ok(Self { id, data, c, z});
            })
        });

        if result.is_err() {
            println!("{}", result.err().unwrap().to_string());
            return Err(ThresholdCryptoError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl PartialEq for Cks05CoinShare  {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.data.eq(&other.data) && self.c.eq(&other.c) && self.z.eq(&other.z)
    }
}

impl Cks05ThresholdCoin {
    pub fn create_share(name: &[u8], sk: &Cks05PrivateKey, rng: &mut RNG) -> Cks05CoinShare {
        let q = sk.get_order();

        let c_bar = H(name, &sk.get_group());
        let data = c_bar.pow(&sk.xi);

        let s = BigImpl::new_rand(&sk.get_group(), &q, rng);

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

        let z = s
            .add(&BigImpl::rmul(&c, &sk.xi, &q))
            .rmod(&q);

        Cks05CoinShare { id: sk.id, data, c, z,}
    }

    pub fn verify_share(share: &Cks05CoinShare, name: &[u8], pk: &Cks05PublicKey) -> bool {
        let c_bar = H(name, &share.get_group());

        let h = 
            GroupElement::new(&pk.group)
            .pow(&share.z)
            .div(
                &pk.verification_key[(share.id -1) as usize]
                .pow(&share.c)
            );

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

    let mut res = BigImpl::from_bytes(&group, &buf);
    res.rmod(&group.get_order());

    GroupElement::new_pow_big(&group, &res)
}

fn H1(g1: &GroupElement, g2: &GroupElement, g3: &GroupElement, g4: &GroupElement, g5: &GroupElement, g6: &GroupElement) -> BigImpl {
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

    let mut res = BigImpl::from_bytes(&g1.get_group(), &buf);
    res.rmod(&g1.get_order());

    res
}

fn H2(g: &GroupElement) -> u8 {
    let mut buf: Vec<u8> = Vec::new();

    buf = [&buf[..], &g.to_bytes()[..]].concat();

    let mut hash = HASH256::new();
    hash.process_array(&buf);

    let h = hash.hash();
    
    buf = Vec::new();
    buf = [&buf[..], &h].concat();

    let nbits = g.get_order().nbytes() * 8;

    if nbits > buf.len() * 4 {
        let mut g: [u8; 32];
        for i in 1..(((nbits - buf.len() * 4) / buf.len() * 8) as f64).ceil() as isize {
            g = h.clone();
            hash.process_array(&[&g[..], &(i.to_le_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    let mut res = BigImpl::from_bytes(&g.get_group(), &buf);
    res.rmod(&BigImpl::new_int(&g.get_group(), 2));

    let bit = res.to_bytes()[res.nbytes() - 1];

    bit
}
