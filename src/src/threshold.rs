use miracl_core::rand::{RAND, RAND_impl};
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::dbig::DBIG;
use miracl_core::bls12381::rom;

pub struct ECGroup {
    pub q: BIG,
    pub g: ECP
}
pub trait Ciphertext {
    fn get_msg(&self) -> Vec<u8>;
    fn get_label(&self) -> Vec<u8>;
}

pub trait DecryptionShare {
    fn get_id(&self) -> u8;
    fn get_data(&self) -> ECP2;
}

pub trait CipherPrivateKey {
    fn encrypt(msg:&[u8]) -> dyn Ciphertext;
    fn verify_ciphertext() -> bool;
    fn verify_share() -> bool;
    fn assemble(ct: &impl Ciphertext, shares: &Vec<impl DecryptionShare>) -> Vec<u8>;
}

pub fn gen_key_values(k: u8, n:u8, rng: &mut impl RAND) -> (ECP2, Vec<BIG>, Vec<ECP>) {
    let x = BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng);
    let mut y = ECP2::generator();
    y = y.mul(&x);

    let s = BIG::randomnum(&BIG::new_ints(&rom::CURVE_ORDER), rng);
    let mut g_hat = ECP::generator();
    g_hat = g_hat.mul(&s);

    let (shares, h) = shamir_share(&x, &ECP::generator(), &k, &n, rng);

    (y, shares, h)
}  

pub fn shamir_share(x: &BIG, g:&ECP, k: &u8, n: &u8, rng: &mut impl RAND) -> (Vec<BIG>, Vec<ECP>) {
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

pub fn eval_pol(x: &BIG, a: &Vec<BIG>) ->  BIG {
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

pub fn lagrange_coeff(indices: &[u8], i: isize) -> BIG {
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


pub fn interpolate_exp(shares: &Vec<impl DecryptionShare>) -> ECP2 { 
    let ids:Vec<u8> = (0..shares.len()).map(|x| shares[x].get_id()).collect();
    let mut rY = ECP2::new();

    for i in 0..shares.len() {
        let l = lagrange_coeff(&ids, shares[i].get_id() as isize);
        let mut ui = shares[i].get_data().clone();
        ui = ui.mul(&l);
        if i == 0 {
            rY = ui;
        } else {
            rY.add(&ui);
        }
    }

    rY
}


pub fn interpolate(shares: Vec<BIG>) -> BIG {
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