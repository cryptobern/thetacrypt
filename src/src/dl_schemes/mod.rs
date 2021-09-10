use crate::interface::Share;

use self::dl_groups::{dl_group::DlGroup, pairing::PairingEngine};

pub mod dl_groups;
pub mod keygen;
pub mod common;
pub mod ciphers;
pub mod signatures;
pub mod coins;

pub trait DlDomain: PairingEngine {
    fn is_pairing_friendly() -> bool;
}

pub trait DlShare<G: DlGroup>: Share {
    fn get_data(&self) -> G;
}