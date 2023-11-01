use serde::{Serialize, Deserialize};

use theta_schemes::{interface::ThresholdCryptoError, keys::PrivateKey};

pub(crate) type InstanceId = String;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Key {
    pub id: String,
    pub(crate) is_default_for_scheme_and_group: bool,
    pub(crate) is_default_for_operation: bool,
    pub sk: PrivateKey
}