#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ThresholdSchemeCode {
    Bz03 = 0,
    Sg02 = 1,
    Bls04 = 2,
    Cks05 = 3,
    Frost = 4,
    Sh00 = 5,
}
impl ThresholdSchemeCode {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ThresholdSchemeCode::Bz03 => "Bz03",
            ThresholdSchemeCode::Sg02 => "Sg02",
            ThresholdSchemeCode::Bls04 => "Bls04",
            ThresholdSchemeCode::Cks05 => "Cks05",
            ThresholdSchemeCode::Frost => "Frost",
            ThresholdSchemeCode::Sh00 => "Sh00",
        }
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum GroupCode {
    Bls12381 = 0,
    Bn254 = 1,
    Ed25519 = 2,
    Rsa512 = 3,
    Rsa1024 = 4,
    Rsa2048 = 5,
    Rsa4096 = 6,
}
impl GroupCode {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            GroupCode::Bls12381 => "Bls12381",
            GroupCode::Bn254 => "Bn254",
            GroupCode::Ed25519 => "Ed25519",
            GroupCode::Rsa512 => "Rsa512",
            GroupCode::Rsa1024 => "Rsa1024",
            GroupCode::Rsa2048 => "Rsa2048",
            GroupCode::Rsa4096 => "Rsa4096",
        }
    }
}
