use asn1::{WriteError, ParseError};
use chacha20poly1305::{Key, ChaCha20Poly1305, aead::{NewAead, Aead}, Nonce};
use theta_proto::scheme_types::Group;
use crate::{interface::{ThresholdScheme, ThresholdCryptoError}, scheme_types_impl::GroupDetails};
use derive::{DlShare};
use crate::interface::Serializable;
use mcore::hash256::HASH256;
use rasn::{AsnType, Encoder, Encode, Decode};

use crate::{dl_schemes::{ common::{gen_symm_key, xor, interpolate}}, rand::RNG, interface::{ThresholdCipherParams, DlShare}};
use crate::group::{GroupElement};
use crate::dl_schemes::bigint::BigImpl;
pub struct Sg02ThresholdCipher {}

#[derive(Clone, Debug, PartialEq)]
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

impl Serializable for Sg02PublicKey {
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
    
                w.write_element(&self.g_bar.to_bytes().as_slice())?;
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

                let bytes = d.read_element::<&[u8]>()?;
                let g_bar = GroupElement::from_bytes(&bytes, &group, Option::None);

                Ok(Self{n, k, group, y, verification_key, g_bar})
            })
        });

        if result.is_err() {
            println!("{}", result.err().unwrap().to_string());
            return Err(ThresholdCryptoError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

#[derive(Clone, Debug, PartialEq)]
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

impl Serializable for Sg02PrivateKey {
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
                let res = Sg02PublicKey::deserialize(&pubbytes.to_vec());
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

#[derive(Clone, PartialEq)]
pub struct Sg02Ciphertext{
    label: Vec<u8>,
    msg: Vec<u8>,
    u: GroupElement,
    u_bar: GroupElement,
    e: BigImpl,
    f: BigImpl,
    c_k: Vec<u8>,
}

impl Serializable for Sg02Ciphertext {
    fn serialize(&self) -> Result<Vec<u8>, ThresholdCryptoError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&self.get_group().get_code())?;
                w.write_element(&self.label.as_slice())?;
                w.write_element(&self.msg.as_slice())?;
                w.write_element(&self.u.to_bytes().as_slice())?;
                w.write_element(&self.u_bar.to_bytes().as_slice())?;
                w.write_element(&self.e.to_bytes().as_slice())?;
                w.write_element(&self.f.to_bytes().as_slice())?;
                w.write_element(&self.c_k.as_slice())?;
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
                let label = d.read_element::<&[u8]>()?.to_vec();
                let msg = d.read_element::<&[u8]>()?.to_vec();
                
                let bytes = d.read_element::<&[u8]>()?;
                let u = GroupElement::from_bytes(&bytes, &group, Option::None);
                
                let bytes = d.read_element::<&[u8]>()?;
                let u_bar = GroupElement::from_bytes(&bytes, &group, Option::None);

                let bytes = d.read_element::<&[u8]>()?;
                let e = BigImpl::from_bytes(&group, &bytes);

                let bytes = d.read_element::<&[u8]>()?;
                let f = BigImpl::from_bytes(&group, &bytes);

                let c_k = d.read_element::<&[u8]>()?.to_vec();

                return Ok(Sg02Ciphertext { label, msg, u, u_bar, e, f, c_k });
            })
        });

        if result.is_err() {
            println!("{}", result.err().unwrap().to_string());
            return Err(ThresholdCryptoError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl Sg02Ciphertext {
    pub fn new(label: Vec<u8>,
        msg: Vec<u8>,
        u: GroupElement,
        u_bar: GroupElement,
        e: BigImpl,
        f: BigImpl,
        c_k: Vec<u8>) -> Self{
            Self {msg, label, u, u_bar, e, f, c_k}
        }
    pub fn get_msg(&self) -> Vec<u8> { self.msg.clone() }
    pub fn get_label(&self) -> Vec<u8> { self.label.clone() }
    pub fn get_scheme(&self) -> ThresholdScheme { ThresholdScheme::Sg02 }
    pub fn get_group(&self) -> &Group { self.e.get_group() }
}

#[derive(Clone, PartialEq, DlShare)]
pub struct Sg02DecryptionShare {
    id: u16,
    label: Vec<u8>,
    data: GroupElement,
    ei: BigImpl,
    fi: BigImpl,
}

impl Sg02DecryptionShare {
    pub fn get_label(&self) -> &[u8]{ &self.label }
    pub fn get_scheme(&self) -> ThresholdScheme { ThresholdScheme::Sg02 }
}

impl Serializable for Sg02DecryptionShare {
    fn serialize(&self) -> Result<Vec<u8>, ThresholdCryptoError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                w.write_element(&self.get_group().get_code())?;
                w.write_element(&self.label.as_slice())?;
                w.write_element(&self.data.to_bytes().as_slice())?;
                w.write_element(&self.ei.to_bytes().as_slice())?;
                w.write_element(&self.fi.to_bytes().as_slice())?;
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
                let label = d.read_element::<&[u8]>()?.to_vec();
                
                let bytes = d.read_element::<&[u8]>()?;
                let data = GroupElement::from_bytes(&bytes, &group, Option::None);

                let bytes = d.read_element::<&[u8]>()?;
                let ei = BigImpl::from_bytes(&group, &bytes);

                let bytes = d.read_element::<&[u8]>()?;
                let fi = BigImpl::from_bytes(&group, &bytes);

                return Ok(Self { id, label, data, ei, fi});
            })
        });

        if result.is_err() {
            println!("{}", result.err().unwrap().to_string());
            return Err(ThresholdCryptoError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}

impl Sg02ThresholdCipher {
    pub fn encrypt(msg: &[u8], label: &[u8], pk: &Sg02PublicKey, params: &mut ThresholdCipherParams) -> Sg02Ciphertext {
        let group = pk.get_group();
        let order = group.get_order();
        let rng = &mut params.rng;

        let r = BigImpl::new_rand(&group, &order, rng);
        let u = GroupElement::new_pow_big(&group, &r);
        let ry = pk.y.pow(&r);

        let k = gen_symm_key(rng);
        let key = Key::from_slice(&k);
        let cipher = ChaCha20Poly1305::new(key);
        let encryption: Vec<u8> = cipher
            .encrypt(Nonce::from_slice(&ry.to_bytes()[0..12]),  msg)
            .expect("Failed to encrypt plaintext");
        
        let c_k = xor(h(&ry), (k).to_vec());
      
        let s = BigImpl::new_rand(&group, &order, rng);
        let w = GroupElement::new_pow_big(&group, &s);

        let w_bar = pk.g_bar.pow(&s);
        let u_bar = pk.g_bar.pow(&r);

        let e = h1(&c_k, &label, &u, &w, &u_bar, &w_bar);

        let f = s
            .add(&BigImpl::rmul(&e, &r, &order))
            .rmod(&order);

        let c = Sg02Ciphertext{label:label.to_vec(), msg:encryption, c_k:c_k.to_vec(), u:u, u_bar:u_bar, e:e, f:f};
        c
    }

    pub fn verify_ciphertext(ct: &Sg02Ciphertext, pk: &Sg02PublicKey) -> bool {
        let w = GroupElement::new_pow_big(&pk.group, &ct.f).div(&ct.u.pow(&ct.e));

        let w_bar = 
            pk.g_bar
            .pow(&ct.f)
            .div(
                &ct.u_bar
                .pow(&ct.e)
            );

        let e2 = h1(&ct.c_k, &ct.label, &ct.u, &w, &ct.u_bar, &w_bar);
        ct.e.equals(&e2)
    }
    
    pub fn partial_decrypt(ct: &Sg02Ciphertext, sk: &Sg02PrivateKey, params: &mut ThresholdCipherParams) -> Sg02DecryptionShare {
        let group = sk.get_group();
        let order = group.get_order();

        let data = ct.u.pow(&sk.xi);
        let si = BigImpl::new_rand(&group, &order, &mut params.rng);

        let ui_bar = ct.u.pow(&si);
        let hi_bar = GroupElement::new(&group).pow(&si);

        let ei = h2(&data, &ui_bar, &hi_bar);
        let fi = si.add(&BigImpl::rmul(&sk.xi, &ei, &order)).rmod(&order);

        Sg02DecryptionShare { id:sk.id.clone(), data:data, label:ct.label.clone(), ei:ei, fi:fi}
    }

    pub fn verify_share(share: &Sg02DecryptionShare, ct: &Sg02Ciphertext, pk: &Sg02PublicKey) -> bool {
        let ui_bar = 
            ct.u.pow(&share.fi)
            .div(
                &share.data
                .pow(&share.ei)
            );

        let hi_bar = 
            GroupElement::new(&pk.group)
            .pow(&share.fi)
            .div(
                &pk.verification_key[(share.id - 1) as usize]
                .pow(&share.ei)
            );

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
            hash.process_array(&[&g[..], &(i.to_le_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    BigImpl::from_bytes(&g1.get_group(), &buf)
    .rmod(&g1.get_order())
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
            hash.process_array(&[&g[..], &(i.to_le_bytes()[..])].concat());
            g = hash.hash();
            buf = [&buf[..], &g].concat();
        }
    }

    BigImpl::from_bytes(&g1.get_group(), &buf)
    .rmod(&g1.get_order())
}