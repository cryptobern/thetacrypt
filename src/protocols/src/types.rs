use serde::{Serialize, Deserialize};

use schemes::{interface::ThresholdCryptoError, keys::PrivateKey};

pub(crate) type InstanceId = String;

#[derive(Clone, Debug)]
pub enum ProtocolError {
    SchemeError(ThresholdCryptoError),
    InvalidCiphertext,
    InstanceNotFound,
    InternalError,
}

impl From<ThresholdCryptoError> for ProtocolError{
    fn from(tc_error: ThresholdCryptoError) -> Self {
        ProtocolError::SchemeError(tc_error)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Key {
    pub id: String,
    pub(crate) is_default_for_scheme_and_group: bool,
    pub(crate) is_default_for_operation: bool,
    pub sk: PrivateKey
}

