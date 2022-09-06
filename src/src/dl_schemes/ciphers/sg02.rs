use chacha20poly1305::{Key, ChaCha20Poly1305, aead::{NewAead, Aead}, Nonce};
use crate::proto::scheme_types::ThresholdScheme;
use crate::proto::scheme_types::Group;
use derive::{Serializable, DlShare};
use mcore::hash256::HASH256;
use rasn::{AsnType, Encoder, Encode, Decode};

use crate::{dl_schemes::{bigint::{BigImpl, BigInt}, common::{gen_symm_key, xor, interpolate}}, rand::RNG, interface::{ThresholdCipherParams, DlShare}, proto::scheme_types::{Group, ThresholdScheme}};
use crate::group::{GroupElement};

pub struct Sg02ThresholdCipher {}

#[derive(Clone, AsnType, Serializable, PartialEq)]
pub struct Sg02PublicKey {
    n: u16,
    k: u16,
    group: Group,
    y: GroupElement,
    verification_key: Vec<GroupElement>,
    g_bar: GroupElement
}

impl Sg02PublicKey {
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

    pub fn new(n: usize, k: usize, group: &Group, y: &GroupElement, verification_key: &Vec<GroupElement>, g_bar:&GroupElement) -> Self {
        if !y.is_type(&group) || !verification_key[0].is_type(&group) || !g_bar.is_type(&group) {
            panic!("incompatible groups");
        }
        Self {n:n as u16, k:k as u16, group:group.clone(), y:y.clone(), verification_key:verification_key.clone(), g_bar:g_bar.clone()}
    }
}

impl Encode for Sg02PublicKey {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.group.get_code().encode(sequence)?;
            self.n.encode(sequence)?;
            self.k.encode(sequence)?;
            self.y.to_bytes().encode(sequence)?;

            for i in 0..self.verification_key.len() {
                self.verification_key[i].to_bytes().encode(sequence)?;
            }

            self.g_bar.to_bytes().encode(sequence)?;
            Ok(())
        })?;


        Ok(())
    }
}

impl Decode for Sg02PublicKey {
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

            let bytes = Vec::<u8>::decode(sequence)?;
            let g_bar = GroupElement::from_bytes(&bytes, &group, Option::None);


            Ok(Self{n, k, group:group, y, verification_key: verification_key, g_bar})
        })
    }
}

#[derive(Clone, AsnType, Serializable, PartialEq)]
pub struct Sg02PrivateKey {
    id: u16,
    xi: BigImpl,
    pubkey: Sg02PublicKey,
}

impl Sg02PrivateKey {
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

    pub fn new(id:u16, xi: &BigImpl, pubkey: &Sg02PublicKey) -> Self {
        Self {id:id.clone(), xi:xi.clone(), pubkey:pubkey.clone()}
    }

    pub fn get_public_key(&self) -> Sg02PublicKey {
        self.pubkey.clone()
    }
}

impl Encode for Sg02PrivateKey {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.id.encode(sequence)?;
            self.xi.to_bytes().encode(sequence)?;
            self.pubkey.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Sg02PrivateKey {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let id = u16::decode(sequence)?;
            let xi_bytes:Vec<u8> = Vec::<u8>::decode(sequence)?.into();
            let pubkey = Sg02PublicKey::decode(sequence)?;
            let xi = BigImpl::from_bytes(&pubkey.group, &xi_bytes);

            Ok(Self {id, xi, pubkey})
        })
    }
}

#[derive(Clone, AsnType, Serializable, PartialEq)]
pub struct Sg02Ciphertext{
    label: Vec<u8>,
    msg: Vec<u8>,
    u: GroupElement,
    u_bar: GroupElement,
    e: BigImpl,
    f: BigImpl,
    c_k: Vec<u8>,
}

impl Sg02Ciphertext {
    pub fn get_msg(&self) -> Vec<u8> { self.msg.clone() }
    pub fn get_label(&self) -> Vec<u8> { self.label.clone() }
    pub fn get_scheme(&self) -> ThresholdScheme { ThresholdScheme::Sg02 }
    pub fn get_group(&self) -> Group { self.e.get_group() }
}

impl Encode for Sg02Ciphertext {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.u.get_group().get_code().encode(sequence)?;
            self.label.encode(sequence)?;
            self.msg.encode(sequence)?;
            self.u.to_bytes().encode(sequence)?;
            self.u_bar.to_bytes().encode(sequence)?;
            self.e.to_bytes().encode(sequence)?;
            self.f.to_bytes().encode(sequence)?;
            self.c_k.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Sg02Ciphertext {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let group = Group::from_code(u8::decode(sequence)?);
            let label = Vec::<u8>::decode(sequence)?;
            let msg = Vec::<u8>::decode(sequence)?;

            let bytes = Vec::<u8>::decode(sequence)?;
            let u = GroupElement::from_bytes(&bytes, &group, Option::None);

            let bytes = Vec::<u8>::decode(sequence)?;
            let u_bar = GroupElement::from_bytes(&bytes, &group, Option::None);

            let bytes = Vec::<u8>::decode(sequence)?;
            let e = BigImpl::from_bytes(&group, &bytes);

            let bytes = Vec::<u8>::decode(sequence)?;
            let f = BigImpl::from_bytes(&group, &bytes);

            let c_k = Vec::<u8>::decode(sequence)?;

            Ok(Self{label, msg, u, u_bar, e, f, c_k})
        })
    }
}

#[derive(Clone, AsnType, Serializable, PartialEq, DlShare)]
pub struct Sg02DecryptionShare {
    id: u16,
    label: Vec<u8>,
    data: GroupElement,
    ei: BigImpl,
    fi: BigImpl,
}

impl Sg02DecryptionShare {
    pub fn get_data(&self) -> GroupElement { self.data.clone() }
    pub fn get_label(&self) -> Vec<u8> { self.label.clone() }
    pub fn get_scheme(&self) -> ThresholdScheme { ThresholdScheme::Sg02 }
    pub fn get_group(&self) -> Group { self.data.get_group() }
}

impl Encode for Sg02DecryptionShare {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.data.get_group().get_code().encode(sequence)?;
            self.id.encode(sequence)?;
            self.label.encode(sequence)?;
            self.data.to_bytes().encode(sequence)?;
            self.ei.to_bytes().encode(sequence)?;
            self.fi.to_bytes().encode(sequence)?;
            Ok(())
        })?;


        Ok(())
    }
}

impl Decode for Sg02DecryptionShare {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let group = Group::from_code(u8::decode(sequence)?);
            let id = u16::decode(sequence)?;
            let label = Vec::<u8>::decode(sequence)?;

            let bytes = Vec::<u8>::decode(sequence)?;
            let data = GroupElement::from_bytes(&bytes, &group, Option::None);

            let bytes = Vec::<u8>::decode(sequence)?;
            let ei = BigImpl::from_bytes(&group, &bytes);

            let bytes = Vec::<u8>::decode(sequence)?;
            let fi = BigImpl::from_bytes(&group, &bytes);

            Ok(Self{id, label, data, ei, fi})
        })
    }
}


impl Sg02ThresholdCipher {
    pub fn encrypt(msg: &[u8], label: &[u8], pk: &Sg02PublicKey, params: &mut ThresholdCipherParams) -> Sg02Ciphertext {
        let rng = &mut params.rng;
        let r = BigImpl::new_rand(&pk.group, &pk.y.get_order(), rng);
        let mut u = GroupElement::new(&pk.group);
        u.pow(&r);

        let mut ry = pk.y.clone();
        ry.pow(&r);

        let k = gen_symm_key(rng);
        let key = Key::from_slice(&k);
        let cipher = ChaCha20Poly1305::new(key);
        let encryption: Vec<u8> = cipher
            .encrypt(Nonce::from_slice(&ry.to_bytes()[0..12]),  msg)
            .expect("Failed to encrypt plaintext");
        
        let c_k = xor(h(&ry), (k).to_vec());
      
        let s = BigImpl::new_rand(&pk.group, &pk.y.get_order(), rng);
        let mut w = GroupElement::new(&pk.group);
        w.pow(&s);

        let mut w_bar = pk.g_bar.clone();
        w_bar.pow(&s);

        let mut u_bar = pk.g_bar.clone();
        u_bar.pow(&r);

        let e = h1(&c_k, &label, &u, &w, &u_bar, &w_bar);

        let mut f = s.clone();
        f.add(&BigImpl::rmul(&e, &r, &pk.y.get_order()));
        f.rmod(&pk.y.get_order());

        let c = Sg02Ciphertext{label:label.to_vec(), msg:encryption, c_k:c_k.to_vec(), u:u, u_bar:u_bar, e:e, f:f};
        c
    }

    pub fn verify_ciphertext(ct: &Sg02Ciphertext, pk: &Sg02PublicKey) -> bool {
        let mut w = GroupElement::new(&pk.group);
        w.pow(&ct.f);

        let mut rhs = ct.u.clone();
        rhs.pow(&ct.e);

        w.div(&rhs);

        let mut w_bar = pk.g_bar.clone();
        w_bar.pow(&ct.f);

        let mut rhs = ct.u_bar.clone();
        rhs.pow(&ct.e);

        w_bar.div(&rhs);

        let e2 = h1(&ct.c_k, &ct.label, &ct.u, &w, &ct.u_bar, &w_bar);

        ct.e.equals(&e2)
    }
    
    pub fn partial_decrypt(ct: &Sg02Ciphertext, sk: &Sg02PrivateKey, params: &mut ThresholdCipherParams) -> Sg02DecryptionShare {
        let mut data = ct.u.clone();
        data.pow(&sk.xi);

        let si = BigImpl::new_rand(&sk.xi.get_group(), &sk.xi.get_group().get_order(), &mut params.rng);

        let mut ui_bar = ct.u.clone();
        ui_bar.pow(&si);

        let mut hi_bar = GroupElement::new(&sk.xi.get_group());
        hi_bar.pow(&si);

        let ei = h2(&data, &ui_bar, &hi_bar);
        let mut fi = si.clone();
        fi.add(&BigImpl::rmul(&sk.xi, &ei, &sk.xi.get_group().get_order()));
        fi.rmod(&sk.xi.get_group().get_order());

        Sg02DecryptionShare { id:sk.id.clone(), data:data, label:ct.label.clone(), ei:ei, fi:fi}
    }

    pub fn verify_share(share: &Sg02DecryptionShare, ct: &Sg02Ciphertext, pk: &Sg02PublicKey) -> bool {
        let mut ui_bar = ct.u.clone();
        ui_bar.pow(&share.fi);

        let mut rhs = share.data.clone();
        rhs.pow(&share.ei);

        ui_bar.div(&rhs);

        let mut hi_bar = GroupElement::new(&pk.group);
        hi_bar.pow(&share.fi);

        let mut rhs = pk.verification_key[(share.id -1) as usize].clone();
        rhs.pow(&share.ei);

        hi_bar.div(&rhs);

        let ei2 = h2(&share.data, &ui_bar, &hi_bar);

        share.ei.equals(&ei2)
    }

    pub fn assemble(shares: &Vec<Sg02DecryptionShare>, ct: &Sg02Ciphertext) -> Vec<u8> {
        let ry = interpolate(shares);
        let k = xor(h(&ry), ct.c_k.clone());
        let key = Key::from_slice(&k);
        let cipher = ChaCha20Poly1305::new(key);
        let msg = cipher
            .decrypt(Nonce::from_slice(&ry.to_bytes()[0..12]), ct.msg.as_ref())
            .expect("Failed to decrypt ciphertext. Make sure you have enough valid decryption shares");
        
        msg
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

fn h1(m1: &[u8], m2:&[u8], g1: &GroupElement, g2: &GroupElement, g3: &GroupElement, g4: &GroupElement) -> BigImpl {
    let mut buf:Vec<u8> = Vec::new();
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

    let nbits = q.nbytes()*8;
    
    if nbits > buf.len()*4 {
        let mut g:[u8;32];
        for i in 1..(((nbits - buf.len()*4)/buf.len()*8) as f64).ceil() as isize {
            g = h.clone();
            hash.process_array(&[&g[..], &(i.to_ne_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    let mut res = BigImpl::from_bytes(&g1.get_group(), &buf);
    res.rmod(&g1.get_order());

    res
}

fn h2(g1: &GroupElement, g2: &GroupElement, g3: &GroupElement) -> BigImpl {
    let mut buf:Vec<u8> = Vec::new();
    let q = g1.get_order();

    buf = [&buf[..], &g1.to_bytes()[..]].concat();
    buf = [&buf[..], &g2.to_bytes()[..]].concat();
    buf = [&buf[..], &g3.to_bytes()[..]].concat();

    let mut hash = HASH256::new();
    hash.process_array(&buf);
    let h = hash.hash();

    buf = Vec::new();
    buf = [&buf[..], &h].concat();
    
    let nbits = q.nbytes()*8;
    
    if nbits > buf.len()*4 {
        let mut g:[u8;32];
        for i in 1..(((nbits - buf.len()*4)/buf.len()*8) as f64).ceil() as isize {
            g = h.clone();
            hash.process_array(&[&g[..], &(i.to_ne_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    let mut res = BigImpl::from_bytes(&g1.get_group(), &buf);
    res.rmod(&g1.get_order());

    res
}

impl Sg02ThresholdCipher {
    pub fn test_tamper_ciphertext(ctxt: &Sg02Ciphertext) -> Sg02Ciphertext{
        let mut tampered_ctxt = ctxt.clone();
        tampered_ctxt.label = Vec::from("Mallory");
        tampered_ctxt
    }
}