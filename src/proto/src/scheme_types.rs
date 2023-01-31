#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ThresholdScheme {
    Bz03 = 0,
    Sg02 = 1,
    Bls04 = 2,
    Cks05 = 3,
    Frost = 4,
    Sh00 = 5,
}
impl ThresholdScheme {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ThresholdScheme::Bz03 => "Bz03",
            ThresholdScheme::Sg02 => "Sg02",
            ThresholdScheme::Bls04 => "Bls04",
            ThresholdScheme::Cks05 => "Cks05",
            ThresholdScheme::Frost => "Frost",
            ThresholdScheme::Sh00 => "Sh00",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "Bz03" => Some(Self::Bz03),
            "Sg02" => Some(Self::Sg02),
            "Bls04" => Some(Self::Bls04),
            "Cks05" => Some(Self::Cks05),
            "Frost" => Some(Self::Frost),
            "Sh00" => Some(Self::Sh00),
            _ => None,
        }
    }

    pub fn get_id(&self) -> u8 {
        *self as u8
    }

    pub fn from_id(id: u8) -> ThresholdScheme {
        match id {
            0 => Self::Bz03,
            1 => Self::Sg02,
            2 => Self::Bls04,
            3 => Self::Cks05,
            4 => Self::Frost,
            5 => Self::Sh00,
            _ => panic!("unknown scheme id")
        }
    }
} 

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Group {
    Bls12381 = 0,
    Bn254 = 1,
    Ed25519 = 2,
    Rsa512 = 3,
    Rsa1024 = 4,
    Rsa2048 = 5,
    Rsa4096 = 6,
}
impl Group {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Group::Bls12381 => "Bls12381",
            Group::Bn254 => "Bn254",
            Group::Ed25519 => "Ed25519",
            Group::Rsa512 => "Rsa512",
            Group::Rsa1024 => "Rsa1024",
            Group::Rsa2048 => "Rsa2048",
            Group::Rsa4096 => "Rsa4096",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "Bls12381" => Some(Self::Bls12381),
            "Bn254" => Some(Self::Bn254),
            "Ed25519" => Some(Self::Ed25519),
            "Rsa512" => Some(Self::Rsa512),
            "Rsa1024" => Some(Self::Rsa1024),
            "Rsa2048" => Some(Self::Rsa2048),
            "Rsa4096" => Some(Self::Rsa4096),
            _ => None,
        }
    }

/*  Enum representing the implemented groups (incl. order and whether they support pairings). Each
    group has a code (8-bit unsigned integer) that's used to encode the group when serializing
    group elements. 

    TODO: change code to standard way of encoding EC groups */
    pub fn is_dl(&self) -> bool {
        match self {
            Self::Bls12381 => true,
            Self::Bn254 => true,
            Self::Ed25519 => true,
            Self::Rsa512 => false,
            Self::Rsa1024 => false,
            Self::Rsa2048 => false,
            Self::Rsa4096 => false,
        }
    }

    pub fn get_code(&self) -> u8 {
        match self {
            Self::Bls12381 => 0,
            Self::Bn254 => 1,
            Self::Ed25519 => 2,
            Self::Rsa512 => 3,
            Self::Rsa1024 => 3,
            Self::Rsa2048 => 4,
            Self::Rsa4096 => 5,
        }
    }

    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Bls12381,
            1 => Self::Bn254,
            2 => Self::Ed25519,
            3 => Self::Rsa512,
            4 => Self::Rsa1024,
            5 => Self::Rsa2048,
            6 => Self::Rsa4096,
            _ => panic!("invalid code")
        }
    }

    pub fn get_order(&self) -> BigImpl {
        match self {
            Self::Bls12381 => Bls12381::get_order(),
            Self::Bn254 => Bn254::get_order(),
            Self::Ed25519 => Ed25519::get_order(),
            _ => panic!("not applicable")
        }
    }

    pub fn supports_pairings(&self) -> bool {
        match self {
            Self::Bls12381 => true,
            Self::Bn254 => true,
            Self::Ed25519 => false,
            Self::Rsa512 => false,
            Self::Rsa1024 => false,
            Self::Rsa2048 => false,
            Self::Rsa4096 => false,
        }
    }
}
