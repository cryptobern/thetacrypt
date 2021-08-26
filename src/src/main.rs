#![allow(non_snake_case)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use miracl_core::rand::{RAND, RAND_impl};
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::big;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::dbig::DBIG;
use miracl_core::bls12381::rom;
use miracl_core::bls12381::pair;
use miracl_core::hmac::*;
use miracl_core::aes::*;
use miracl_core::hash256::*;

use std::time::SystemTime;

pub struct ECGroup {
    q: BIG,
    g: ECP
}

pub struct PublicKey {
    y: ECP2,
    verificationKey: Vec<ECP>,
    g_hat: ECP,
    group: ECGroup,
}

pub struct PrivateKey {
    id: u8,
    xi: BIG,
    pubkey: PublicKey,
}

impl PrivateKey {
    fn partial_decrypt(&self, cipher: &Ciphertext) -> DecryptionShare {
        let mut u = cipher.u.clone();
        u = u.mul(&self.xi);

        DecryptionShare {id:self.id.clone(), data: u.clone()}
    }
}

fn H(g: &ECP2, m: &Vec<u8>) -> ECP {
    let a = ECP::hap2point(&g.getx().geta());

    let mut bytes: Vec<u8> = vec![0;256];
    g.tobytes(&mut bytes, false);

    let mut h = HASH256::new();
    h.process_array(&[&bytes[..], &m[..]].concat());

    let h = [&vec![0;big::MODBYTES - 32][..], &h.hash()[..]].concat();

    let mut s = BIG::frombytes(&h);
    s.rmod(&BIG::new_ints(&rom::CURVE_ORDER));

    ECP::generator().mul(&s)

}

impl PublicKey {
    fn encrypt(&self, msg:Vec<u8>, label:Vec<u8>, rng: &mut impl RAND) -> Ciphertext {
        let prk: &mut [u8] = &mut[0;32];
        let mut ikm: Vec<u8> = Vec::new();
        for _ in 0..32 {
            ikm.push(rng.getbyte());
        }

        let salt: Vec<u8> = Vec::new();
        hkdf_extract(MC_SHA2, 32, prk, Option::Some(&salt), &ikm);

        let k: &mut[u8] = &mut[0;32];
        hkdf_expand(MC_SHA2, 32, k, 16, prk, &[0]);

        let q = BIG::new_ints(&rom::CURVE_ORDER);
        let r = BIG::randomnum(&q, rng);
        let mut u = ECP2::generator();
        u = u.mul(&r);

        let mut rY = self.y.clone();
        rY = rY.mul(&r);

        let c_k = xor(G(&rY), (*k).to_vec());

        let mut encryption: Vec<u8> = vec![0; msg.len()];
        cbc_iv0_encrypt(k, &msg, &mut encryption);

        let hr = H(&u, &encryption).mul(&r);

        let c = Ciphertext{label:label, msg:encryption, c_k:c_k.to_vec(), u:u, hr:hr};
        c
    }


    fn assemble(&self, ct:&Ciphertext, shares:&Vec<DecryptionShare>) -> Vec<u8> {
        let rY = interpolate_exp(shares);

        let key = xor(G(&rY), ct.c_k.clone());
        
        let mut msg: Vec<u8> = vec![0; 44];
        cbc_iv0_decrypt(&key, &ct.msg.clone(), &mut msg);

        msg
    }

    fn verify_ciphertext(&self, ct: &Ciphertext) -> bool {
        let h = H(&ct.u, &ct.msg);

        let mut lhs =  pair::ate(&ct.u, &h);
        lhs = pair::fexp(&lhs);

        let mut rhs = pair::ate(&ECP2::generator(), &ct.hr);
        rhs = pair::fexp(&rhs);
        
        lhs.equals(&rhs)

    }

    fn verify_decryption_share(&self, share: &DecryptionShare, ct: &Ciphertext) -> bool {
        let mut lhs =  pair::ate( &share.data, &ECP::generator());
        lhs = pair::fexp(&lhs);

        let mut rhs = pair::ate(&ct.u, &self.verificationKey[(&share.id - 1) as usize]);
        rhs = pair::fexp(&rhs);
        
        lhs.equals(&rhs)
    }
}

fn interpolate_exp(shares: &Vec<DecryptionShare>) -> ECP2 { 
    let ids:Vec<u8> = (0..shares.len()).map(|x| shares[x].id).collect();
    let mut rY = ECP2::new();

    for i in 0..shares.len() {
        let l = lagrange_coeff(&ids, shares[i].id as isize);
        let mut ui = shares[i].data.clone();
        ui = ui.mul(&l);
        if i == 0 {
            rY = ui;
        } else {
            rY.add(&ui);
        }
    }

    rY
}


fn interpolate(shares: Vec<BIG>) -> BIG {
    let mut key: BIG = BIG::new_int(0);
    let q = BIG::new_ints(&rom::CURVE_ORDER);
    let ids:Vec<u8> =  (1..shares.len()+1).map(|x| x as u8).collect();

    for i in 0..shares.len() {
        let mut prod = BIG::new_big(&lagrange_coeff(&ids, (i+1) as isize));
        let mut tmp = BIG::mul(&prod, &shares[i]);
        prod = tmp.dmod(&q);
        
        key.add(&prod);
    }
    key.rmod(&q);

    BIG::fromstring(key.tostring())
}

fn xor(v1: Vec<u8>, v2: Vec<u8>) -> Vec<u8> {
    let v3: Vec<u8> = v1
    .iter()
    .zip(v2.iter())
    .map(|(&x1, &x2)| x1 ^ x2)
    .collect();

    v3
}

// hash ECP to bit string
fn G(x: &ECP2) -> Vec<u8> {
    let mut res:Vec<u8> = vec![0;100];
    x.getx().tobytes(&mut res);

    let mut h = HASH256::new();
    h.process_array(&res);
    
    let r = h.hash().to_vec();
    r
}

pub struct DecryptionShare {
    id: u8,
    data: ECP2
}

pub struct Ciphertext {
    label: Vec<u8>,
    msg: Vec<u8>,
    c_k: Vec<u8>,
    u: ECP2,
    hr: ECP
}

pub fn printbinary(array: &[u8], caption: Option<&str>) {
    if caption.is_some() {
        print!("{}", caption.unwrap());
    }
    for i in 0..array.len() {
        print!("{:02X}", array[i])
    }
    println!("")
}

impl Clone for PublicKey {
    fn clone(&self) -> PublicKey {
        return PublicKey {y:self.y.clone(), verificationKey:self.verificationKey.clone(), g_hat:self.g_hat.clone(), group:ECGroup { q:self.group.q.clone(), g: ECP::generator() }};
    }
}

#[allow(non_snake_case)]
fn gen_keys(k: u8, n:u8, rng: &mut impl RAND) -> (PublicKey, Vec<PrivateKey>) {
    let x = BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng);
    let mut y = ECP2::generator();
    y = y.mul(&x);

    let s = BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng);
    let mut g_hat = ECP::generator();
    g_hat = g_hat.mul(&s);

    let (shares, h) = shamir_share(&x, &ECP::generator(), &k, &n, rng);
    let pk = PublicKey {y:y.clone(), verificationKey:h.clone(), g_hat:g_hat.clone(), group:ECGroup { q:BIG::new_ints(&rom::CURVE_ORDER), g:ECP::generator() }};
    let mut sk: Vec<PrivateKey> = Vec::new();
    
    for j in 1..n+1 {
        sk.push(PrivateKey {id:j, xi:shares[(j -1) as usize], pubkey:pk.clone()});
    }

    (pk, sk)
}  

fn shamir_share(x: &BIG, g:&ECP, k: &u8, n: &u8, rng: &mut impl RAND) -> (Vec<BIG>, Vec<ECP>) {
    let mut coeff: Vec<BIG> = Vec::new();
    let q = BIG::new_ints(&rom::CURVE_ORDER);

    for _ in 0..k-1 {
        coeff.push(BIG::randomnum(&q, rng));
    }

    coeff.push(BIG::new_big(x));
    let mut shares: Vec<BIG> = Vec::new();
    let mut h: Vec<ECP> = Vec::new();

    for j in 1..n+1 {
        let xi = eval_pol(&BIG::new_int(j as isize), &mut coeff);
        shares.push(xi);
        let mut hi = g.clone();
        hi = hi.mul(&BIG::fromstring(xi.tostring()));
        h.push(hi);
    }

    (shares, h)
}

fn eval_pol(x: &BIG, a: &Vec<BIG>) ->  BIG {
    let len = (a.len()) as isize;
    let mut val = BIG::new_int(0);
    let q = BIG::new_ints(&rom::CURVE_ORDER);
    
    for i in 0..len - 1 {
        let mut tmp = DBIG::new_scopy(&a[i as usize].clone());
        let mut xi = x.clone();

        
        xi.powmod(&BIG::new_int(len - i - 1), &q);
        tmp = BIG::mul(&xi, &tmp.dmod(&q));
        val.add(&tmp.dmod(&q));
    }

    val.add(&a[(len - 1) as usize]);
    val.rmod(&q);

    BIG::fromstring(val.tostring())
}

fn lagrange_coeff(indices: &[u8], i: isize) -> BIG {
    let mut prod = DBIG::new_scopy(&BIG::new_int(1));
    let q = BIG::new_big(&BIG::new_ints(&rom::CURVE_ORDER)); 
    
    for k in 0..indices.len() {
        let j:isize = indices[k].into();

        if i != j {
            let mut ij: BIG;
            let val = (j - i).abs();

            if i > j {
                ij = q.clone();
                ij.sub(&BIG::new_int(val));
            } else {
                ij = BIG::new_int(val);
            }
            ij.invmodp(&q);
            ij.imul(j as isize);

            prod = BIG::mul(&prod.dmod(&q), &ij);
        }
    } 

    let res = prod.dmod(&q);
    res
}

fn hex2string(msg: Vec<u8>) -> String {
    let mut res: String = String::new();
    for i in 0..msg.len() {
        res.push(msg[i] as char);
    }

    res
}

fn main() {
    const K:u8 = 3;
    const N:u8 = 5;

    let mut raw: [u8; 100] = [0; 100];
    let mut rng = RAND_impl::new();
    rng.clean();

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);

    match now {
        Ok(_n) => {
            let ms = _n.as_millis();
            for i in 0..15 {
                raw[i] = (ms << i) as u8
            }

            rng.seed(16, &raw);
        },
        Err(_) => {
            for i in 0..100 {
                raw[i] = i as u8
            }

            rng.seed(100, &raw);
        }
    }

    let (pk, sk) = gen_keys(K, N, &mut rng);

    let plaintext = "This is a test!  ";
    let msg: Vec<u8> = String::from(plaintext).as_bytes().to_vec();
    let label: Vec<u8> = String::from("label").as_bytes().to_vec();

    println!("Message: {}", plaintext);
    let ciphertext = pk.encrypt(msg, label, &mut rng);
    printbinary(&ciphertext.msg, Some("Ciphertext: "));

    println!("Ciphertext valid: {}", pk.verify_ciphertext(&ciphertext));

    let mut shares:Vec<DecryptionShare> = Vec::new();
    for i in 0..K {
        shares.push(sk[i as usize].partial_decrypt(&ciphertext));
        println!("Share {} valid: {}", i, pk.verify_decryption_share(&shares[i as usize], &ciphertext));
    }

    let msg = pk.assemble(&ciphertext, &shares);

    println!("Decrypted message: {}", hex2string(msg));
}