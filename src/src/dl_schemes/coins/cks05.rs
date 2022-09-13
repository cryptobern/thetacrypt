#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use derive::{DlShare, Serializable};
use mcore::{hash256::HASH256};
use rasn::{AsnType, Encode, Decode};

use crate::interface::DlShare;
use crate::{group::GroupElement, proto::scheme_types::{Group, ThresholdScheme}, dl_schemes::{common::interpolate}, rand::RNG};
use crate::dl_schemes::bigint::BigImpl;

pub struct Cks05ThresholdCoin {
    g: GroupElement,
}

#[derive(AsnType, Clone, Serializable)]
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

impl Encode for Cks05PublicKey {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.group.get_code().encode(sequence)?;
            self.n.encode(sequence)?;
            self.k.encode(sequence)?;
            self.y.to_bytes().encode(sequence)?;

            for i in 0..self.verification_key.len() {
                self.verification_key[i].to_bytes().encode(sequence)?;
            }
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Cks05PublicKey{
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let group = Group::from_code(u8::decode(sequence)?);
            let n = u16::decode(sequence)?;
            let k = u16::decode(sequence)?;

            let bytes = Vec::<u8>::decode(sequence)?;
            let y = GroupElement::from_bytes(&bytes, &group, Option::None);

            let mut verification_key = Vec::new();

            for _i in 0..n {
                let bytes = Vec::<u8>::decode(sequence)?;
                verification_key.push(GroupElement::from_bytes(&bytes, &group, Option::None));
            }
            Ok(Self{group, n, k, y, verification_key})
        })
    }
}

impl PartialEq for Cks05PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.verification_key.eq(&other.verification_key) &&  self.y.eq(&other.y) 
    }
}

#[derive(AsnType, Clone, Serializable)]
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


impl Encode for Cks05PrivateKey {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.id.encode(sequence)?;
            self.xi.to_bytes().encode(sequence)?;
            self.pubkey.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Cks05PrivateKey {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let id = u16::decode(sequence)?;
            let xi_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let pubkey = Cks05PublicKey::decode(sequence)?;
            let xi = BigImpl::from_bytes(&pubkey.group, &xi_bytes);

            Ok(Self {id, xi, pubkey})
        })
    }
}

impl PartialEq for Cks05PrivateKey{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.xi == other.xi && self.pubkey == other.pubkey
    }
}

#[derive(AsnType, DlShare, Clone, Serializable)]
pub struct Cks05CoinShare {
    id: u16,
    data: GroupElement,
    c: BigImpl,
    z: BigImpl,
}

impl Cks05CoinShare {
    pub fn get_data(&self) -> GroupElement { self.data.clone() }
    pub fn get_scheme(&self) -> ThresholdScheme { ThresholdScheme::Cks05 }
    pub fn get_group(&self) -> Group { self.data.get_group() }
}

impl Encode for Cks05CoinShare {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            (self.data.get_group() as u8).encode(sequence)?;
            self.id.encode(sequence)?;
            self.data.to_bytes().encode(sequence)?;
            self.c.to_bytes().encode(sequence)?;
            self.z.to_bytes().encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Cks05CoinShare {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let group = Group::from_code(u8::decode(sequence)?);
            let id = u16::decode(sequence)?;

            let bytes = Vec::<u8>::decode(sequence)?;
            let data = GroupElement::from_bytes(&bytes, &group, Option::None);
            let c_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let z_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();

            let c = BigImpl::from_bytes(&group, &c_bytes);
            let z = BigImpl::from_bytes(&group, &z_bytes);
            Ok(Self {id, data, c, z})
        })
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
