use crate::interface::Share;

use self::dl_groups::{dl_group::DlGroup, pairing::PairingEngine};

pub mod dl_groups;
pub mod keygen;
pub mod common;
pub mod bz03;
pub mod sg02;

pub trait DlDomain: PairingEngine {
    fn is_pairing_friendly() -> bool;
}

pub trait DlShare<G: DlGroup>: Share {
    fn get_data(&self) -> G;
}