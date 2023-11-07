use theta_schemes::interface::ThresholdCryptoError;
use tonic::async_trait;

#[derive(Clone, Debug)]
pub enum ProtocolError {
    SchemeError(ThresholdCryptoError),
    InvalidCiphertext,
    InstanceNotFound,
    InternalError,
    NotFinished
}

impl From<ThresholdCryptoError> for ProtocolError{
    fn from(tc_error: ThresholdCryptoError) -> Self {
        ProtocolError::SchemeError(tc_error)
    }
}

#[async_trait]
pub trait ThresholdProtocol {
    async fn run(&mut self) -> Result<Vec<u8>, ProtocolError>;
}