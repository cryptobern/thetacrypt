use theta_network::types::message::NetMessage;
use theta_schemes::interface::SchemeError;

//Here one should import the message types defined for the protoccol
use crate::threshold_cipher::message_types::DecryptionShareMessage;

use tonic::async_trait;

#[derive(Clone, Debug)]
pub enum ProtocolError {
    SchemeError(SchemeError),
    InvalidCiphertext,
    InstanceNotFound,
    InternalError,
    NotFinished,
}
pub enum ProtocolMessage{
    Decryption(DecryptionShareMessage)
}

impl From<SchemeError> for ProtocolError {
    fn from(tc_error: SchemeError) -> Self {
        ProtocolError::SchemeError(tc_error)
    }
}



//ROSE: to move to the protocol
// #[async_trait]
pub trait ThresholdRoundProtocol {
    //add s function to handle checks needed to correctly start the protocol, needed or can be put in do round?
    fn do_round(&mut self) -> Result<NetMessage, ProtocolError>;
    fn is_ready_for_next_round(&self) -> bool;
    fn is_finished(&self) -> bool;
    fn update(&mut self, message: NetMessage)-> Result<(), ProtocolError>;
    fn get_result(&self) -> Result<Vec<u8>, ProtocolError>;
    //We can add a compute result function
}
