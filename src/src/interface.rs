#![allow(non_snake_case)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]

pub trait CipherPrivateKey {
    fn encrypt(m: Vec<u8>) -> Vec<u8>;
}