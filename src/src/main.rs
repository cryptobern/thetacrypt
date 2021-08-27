#![allow(non_snake_case)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use miracl_core::rand::{RAND, RAND_impl};

use std::time::SystemTime;

mod bz03;
mod threshold;
mod sg02;

use crate::bz03::*;
use crate::sg02::*;
use crate::threshold::*;

pub fn printbinary(array: &[u8], caption: Option<&str>) {
    if caption.is_some() {
        print!("{}", caption.unwrap());
    }
    for i in 0..array.len() {
        print!("{:02X}", array[i])
    }
    println!("")
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

    let plaintext = "This is a test!  ";
    let msg: Vec<u8> = String::from(plaintext).as_bytes().to_vec();
    let label: Vec<u8> = String::from("label").as_bytes().to_vec();
    println!("Message: {}", plaintext);



    println!("\n--BZ03 Threshold Cipher--");
    let (pk, sk) = bz03_gen_keys(K, N, &mut rng);
    let ciphertext = pk.encrypt(msg, &label, &mut rng);
    printbinary(&ciphertext.get_msg(), Some("Ciphertext: "));

    println!("Ciphertext valid: {}", pk.verify_ciphertext(&ciphertext));

    let mut shares:Vec<BZ03_DecryptionShare> = Vec::new();
    for i in 0..K {
        shares.push(sk[i as usize].partial_decrypt(&ciphertext));
        println!("Share {} valid: {}", i, pk.verify_share(&shares[i as usize], &ciphertext));
    }

    let msg = pk.assemble(&ciphertext, &shares);

    println!("Decrypted message: {}", hex2string(msg));

    println!("\n--SG02 Threshold Cipher--");
    let (pk, sk) = sg02_gen_keys(K, N, &mut rng);
    let msg: Vec<u8> = String::from(plaintext).as_bytes().to_vec();

    let ciphertext = pk.encrypt(msg, &label, &mut rng); 
    printbinary(&ciphertext.get_msg(), Some("Ciphertext: "));
}