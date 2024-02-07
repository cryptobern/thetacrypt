use theta_schemes::interface::{SchemeError, RoundResult};
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


//ROSE: to move to the protocol
pub trait ThresholdRoundProtocol {
    fn do_round(&self) -> Result<Vec<u8>, ProtocolError>;
    fn is_ready_for_next_round(&self) -> bool;
    fn is_finished(&self) -> bool;
    fn update(&self, message: RoundResult);
}
