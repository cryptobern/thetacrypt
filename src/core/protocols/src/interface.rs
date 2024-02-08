use theta_network::types::message::NetMessage;
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

//Eventually this interface should be used by the executor. Add the terminate
#[async_trait]
pub trait ThresholdProtocol {
    async fn run(&mut self) -> Result<Vec<u8>, ProtocolError>;
    // async fn terminate(&mut self) -> Result<(), ProtocolError>; to add to close the channels 
    async fn terminate(&mut self);
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
