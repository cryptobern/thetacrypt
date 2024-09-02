use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use theta_network::types::message::{Channel, NetMessage, NetMessageMetadata};
use theta_schemes::interface::{DecryptionShare, Serializable};

use crate::interface::{ProtocolError, ProtocolMessageWrapper};

// To implement here a serialization that doesn't conflict with the one present at the scheme layer (based on rasn?)
// we can have a generic bytevector already in the message and serialize and deserialize here into the specific types required by the protocol.
// if we absract these steps here the protocol will not care about serializaion/deserialization details.
#[derive(Serialize, Deserialize, Clone)]
pub struct DecryptionShareMessage {
    share: DecryptionShare,
    sender_id: u16
}

impl DecryptionShareMessage {
    pub fn new(share: DecryptionShare) -> Self{
        DecryptionShareMessage{
            share,
            sender_id: 0
        }
    }

    pub fn get_share(&self) -> &DecryptionShare {
        &self.share
    }

    pub fn set_sender_id(&mut self, sender_id: u16){
        self.sender_id = sender_id;
    }

    pub fn get_sender_id(&self) -> u16 {
        return self.sender_id
    }
}

//Here define an enum of possible messages used in the protocol
//In the case of the cipher and all the non-interactive one round protocol here we will have just one value
//for more complex protocol this is not true
#[derive(Serialize, Deserialize, Clone)]
pub enum DecryptionMessage {
    ShareMessage(DecryptionShareMessage),
    Default,
}

impl Default for DecryptionMessage {
    fn default() -> Self {
        DecryptionMessage::Default
    }
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
    
    fn is_default(&self) -> bool {
        match self {
            DecryptionMessage::Default => true,
            _ => false
        }
    }
}

