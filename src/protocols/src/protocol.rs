use cosmos_crypto::interface::ThresholdCryptoError;


type InstanceId = String;

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

// pub trait Protocol: Send + Clone + 'static {
//     fn run(&mut self);
//     fn terminate(&mut self);
// }
