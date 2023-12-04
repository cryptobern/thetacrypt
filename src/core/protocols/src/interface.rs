use theta_schemes::interface::SchemeError;
use tonic::async_trait;

#[derive(Clone, Debug)]
pub enum ProtocolError {
    SchemeError(SchemeError),
    InvalidCiphertext,
    InstanceNotFound,
    InternalError,
    NotFinished,
}

impl From<SchemeError> for ProtocolError {
    fn from(tc_error: SchemeError) -> Self {
        ProtocolError::SchemeError(tc_error)
    }
}

#[async_trait]
pub trait ThresholdProtocol {
    async fn run(&mut self) -> Result<Vec<u8>, ProtocolError>;
}
