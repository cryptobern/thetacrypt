use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use theta_network::types::message::NetMessage;
use theta_schemes::interface::SchemeError;

//Here one should import the message types defined for the protoccol
use crate::threshold_cipher::message_types::DecryptionMessage;

#[derive(Clone, Debug)]
pub enum ProtocolError {
    SchemeError(SchemeError),
    InvalidCiphertext,
    InstanceNotFound,
    InternalError,
    NotFinished,
    InvalidRound,
    InvalidShare,
}
impl From<SchemeError> for ProtocolError {
    fn from(tc_error: SchemeError) -> Self {
        ProtocolError::SchemeError(tc_error)
    }
}

// //Probably we don't need this
// #[derive(Serialize, Deserialize)]
// pub enum ProtocolMessage{
//     Decryption(DecryptionMessage)
// }

//ROSE:
//try to figure out the best modular why to handle messages
pub trait ProtocolMessageWrapper<T>: Send { //Here there was a + Debug. Not sure if needed
    fn unwrap(wrapped: T) -> Result<Box<Self>, ProtocolError>; //we need to Box self because we don't know yet the type
    fn wrap(&self, instance_id: &String) -> Result<T, String>; //T here would be NetMessage
}

//ROSE: to move to the protocol
// Do we need an init() ? Probably yes (with Lukas we discovered that with the two roles of cordinators and signers
// it will be useful to have an init function that thakes care of additional details)
pub trait ThresholdRoundProtocol<T> {
    //add s function to handle checks needed to correctly start the protocol, needed or can be put in do round?
    type ProtocolMessage: ProtocolMessageWrapper<T> + Default;

    fn do_round(&mut self) -> Result<Self::ProtocolMessage, ProtocolError>;
    fn is_ready_for_next_round(&self) -> bool;
    fn is_ready_to_finalize(&self) -> bool;
    fn finalize(&mut self) -> Result<Vec<u8>, ProtocolError>;
    fn update(&mut self, message: Self::ProtocolMessage) -> Result<(), ProtocolError>;
}
