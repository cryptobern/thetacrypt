use std::time::SystemTime;
use mcore::rand::{RAND, RAND_impl};

pub trait PublicKey {}

pub trait PrivateKey {
    type PK: PublicKey;
    fn get_public_key(&self) -> Self::PK;
}

pub trait Ciphertext {
    fn get_msg(&self) -> Vec<u8>;
    fn get_label(&self) -> Vec<u8>;
}
pub trait Share {
    fn get_id(&self) -> u8;
}

pub trait ThresholdCipher {
    type CT: Ciphertext;
    type PK: PublicKey;
    type SK: PrivateKey;
    type SH: Share;

    fn encrypt(msg: &[u8], label: &[u8], pk: &Self::PK, rng: &mut impl RAND) -> Self::CT;
    fn verify_ciphertext(ct: &Self::CT, pk: &Self::PK) -> bool;
    fn verify_share(share: &Self::SH, ct: &Self::CT, pk: &Self::PK) -> bool;
    fn partial_decrypt(ct: &Self::CT, sk: &Self::SK, rng: &mut impl RAND) -> Self::SH;
    fn assemble(shares: &Vec<Self::SH>, ct: &Self::CT) -> Vec<u8>;
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

pub fn new_rand() -> RAND_impl {
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

    rng
}