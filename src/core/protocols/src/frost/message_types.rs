use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use theta_network::types::message::{Channel, NetMessage, NetMessageMetadata};
use theta_schemes::{
    dl_schemes::signatures::frost::{FrostSignatureShare, PublicCommitment},
    interface::{DecryptionShare, Serializable},
};

use crate::interface::{ProtocolError, ProtocolMessageWrapper};

use super::protocol::FrostPrecomputation;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct FrostMessage {
    pub(crate) id: u16,
    pub(crate) data: FrostData,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum FrostData {
    Commitment(PublicCommitment),
    Share(FrostSignatureShare),
    Precomputation(Vec<PublicCommitment>),
    Default,
}

impl Default for FrostData {
    fn default() -> Self {
        FrostData::Default
    }
}

//consider that in protocols like frost you might have different kind of messages that needs the conversion
//for the serialization
// TODO: create macro for the following implementation
impl ProtocolMessageWrapper<NetMessage> for FrostMessage {
    fn unwrap(wrapped: NetMessage) -> Result<Box<FrostMessage>, ProtocolError> {
        let bytes = wrapped.get_message_data().to_owned();
        let result = serde_json::from_str::<FrostMessage>(
            &String::from_utf8(bytes).expect("Error serializing the JSON"),
        );
        match result {
            Ok(message) => {
                let mut msg = message.clone();
                // msg.id = wrapped.get_metadata().get_sender().clone(); //TODO: to implement the logic in the network 
                return Ok(Box::new(msg));
            }
            Err(_) => {
                return Err(ProtocolError::InternalError); //To change the type of error
            }
        };
    }

    ///wrap() provides the logic to correctly create a NetMessage and add the necessary metadata for the medium to use for the delivery.
    // TODO: at this level we are not able to distiguish between the messages (if there is more than one).
    // These functions (or at least wrap) needs to be implemented for each value of the enum
    fn wrap(&self, instance_id: &String) -> Result<NetMessage, String> {
        let message_data = serde_json::to_string(&self)
            .expect("Error in serializing FrostMessage for Vec<u8>")
            .into_bytes();
        let metadata = NetMessageMetadata::new(Channel::Gossip);
        let net_message = NetMessage::new(instance_id.clone(), metadata, message_data);
        return Ok(net_message);
    }
}
