use self::dl_groups::{dl_group::{DlGroup, Group}, pairing::PairingEngine};

pub mod dl_groups;
pub mod common;
pub mod ciphers;
//pub mod signatures;
//pub mod coins;
pub mod bigint;

pub mod pkcs8;

mod keygen_tests;

pub trait DlDomain: PairingEngine {
    fn is_pairing_friendly() -> bool;
    fn name() -> &'static str;
    fn get_type() -> Group;
}