use std::sync::Arc;

use serde::{Serialize, Deserialize};

use schemes::{interface::{ThresholdCryptoError, ThresholdScheme}, keys::PrivateKey, group::Group};

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

// InstanceStatus describes the currenct state of a protocol instance. 
// The field result has meaning only when finished == true. 
#[derive(Debug, Clone)]
pub(crate) struct InstanceStatus {
    pub(crate) started: bool,
    pub(crate) finished: bool,
    pub(crate) result: Result<Vec<u8>, ProtocolError>, 
}

#[derive(Debug)]
pub(crate) enum StateUpdateCommand {
    // Initiate the status for a new instance. The caller must make sure the instance does not already exist, otherwise the status will be overwritten.
    AddNewInstance { 
        instance_id: String,
    },
    // Return the current status of a protocol instance
    GetInstanceStatus { 
        instance_id: String,
        responder: tokio::sync::oneshot::Sender< InstanceStatus >
    },
    // Update the status of an instance.
    UpdateInstanceStatus { 
        instance_id: String,
        new_status: InstanceStatus
    },
    // Returns the private keys that can be used with the given scheme and group
    GetPrivateKeyByType { 
        scheme: ThresholdScheme,
        group: Group,
        responder: tokio::sync::oneshot::Sender< Result<Arc<Key>, String> >
    },
    // Returns all public keys that can be used for encryption.
    GetEncryptionKeys { 
        responder: tokio::sync::oneshot::Sender< Vec<Arc<Key>> >
    },
}


#[derive(Debug)]
pub(crate) enum MessageForwarderCommand {
    GetReceiverForNewInstance {
        instance_id: String,
        responder: tokio::sync::oneshot::Sender< tokio::sync::mpsc::Receiver<Vec<u8>> >
    },
    RemoveReceiverForInstance {
        instance_id: String
    }
}