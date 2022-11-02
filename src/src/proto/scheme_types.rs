#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(u8)]
pub enum ThresholdScheme {
    Bz03 = 0,
    Sg02 = 1,
    Bls04 = 2,
    Cks05 = 3,
    Frost = 4,
    Sh00 = 5,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(u8)]
pub enum Group {
    Bls12381 = 0,
    Bn254 = 1,
    Ed25519 = 2,
    Rsa512 = 3,
    Rsa1024 = 4,
    Rsa2048 = 5,
    Rsa4096 = 6
}


impl ThresholdScheme {
    pub fn is_interactive(&self) -> bool {
        match self {
            Self::Frost => true,
            _ => false
        }
    }

    pub fn get_rounds(&self) -> u8 {
        match self {
            Self::Frost => 2,
            _ => 1
        }
    }
}