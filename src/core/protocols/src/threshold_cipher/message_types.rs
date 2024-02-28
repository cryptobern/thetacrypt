use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use theta_network::types::message::{Channel, NetMessage, NetMessageMetadata};
use theta_schemes::interface::{DecryptionShare, Serializable};

use crate::interface::{ProtocolError, ProtocolMessageWrapper};

// To implement here a serialization that doesn't conflict with the one present at the scheme layer (based on rasn?)
// we can have a generic bytevector already in the message and serialize and deserialize here into the specific types required by the protocol.
// if we absract these steps here the protocol will not care about serializaion/deserialization details.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DecryptionShareMessageOut {
    share: Vec<u8>, //we want to represent the message with the field of cryptographic data already in bytes because at the scheme layer we want to use the custom Serializable trait that uses asn1
}

//TODO: decide if we need this distinction or not
// #[derive(Clone)]
// pub struct DecryptionShareMessageIn {
//     share: theta_schemes::interface::DecryptionShare,
//     sender_id: u16
// }

//Here define an enum of possible messages used in the protocol
//In the case of the cipher and all the non-interactive one round protocol here we will have just one value
//for more complex protocol this is not true
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DecryptionMessage {
    ShareMessageOut(DecryptionShareMessageOut),
}

//consider that in protocols like frost you might have different kind of messages that needs the conversion
//for the serialization

impl ProtocolMessageWrapper<NetMessage> for DecryptionMessage {
    fn unwrap(wrapped: NetMessage) -> Result<Box<DecryptionMessage>, ProtocolError> {
        let bytes = wrapped.get_message_data().to_owned();
        let result = serde_json::from_str::<DecryptionMessage>(
            &String::from_utf8(bytes).expect("Error serializing the JSON"),
        );
        match result {
            Ok(message) => return Ok(Box::new(message)),
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
            .expect("Error in serializing DecryptionShareMessage for Vec<u8>")
            .into_bytes();
        let metadata = NetMessageMetadata::new(Channel::Gossip);
        let net_message = NetMessage::new(instance_id.clone(), metadata, message_data);
        return Ok(net_message);
    }
}

///DecryptionShareMessage wraps the share needed in the protocol.
// TODO: here we can add the functions for the serialization/deserialization so that we don't have them in the protocol logic?
impl DecryptionShareMessageOut {
    pub fn new(share: &theta_schemes::interface::DecryptionShare) -> Self {
        let share_bytes = share
            .to_bytes()
            .expect("Error in serializing decryption share.");
        DecryptionShareMessageOut { share: share_bytes }
    }

    pub fn get_share_bytes(&self) -> &Vec<u8> {
        return &self.share;
    }
}
