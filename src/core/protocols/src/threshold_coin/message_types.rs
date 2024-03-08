use serde::{Deserialize, Serialize};
use theta_network::types::message::{Channel, NetMessage, NetMessageMetadata};
use theta_schemes::interface::CoinShare;

use crate::interface::{ProtocolError, ProtocolMessageWrapper};



#[derive(Serialize, Deserialize)]
pub enum CoinMessage{
    ShareMessage(CoinShare)
}

impl ProtocolMessageWrapper<NetMessage> for CoinMessage {
    fn unwrap(wrapped: NetMessage) -> Result<Box<Self>, crate::interface::ProtocolError> {
        let bytes = wrapped.get_message_data().to_owned();
        let result = serde_json::from_str::<CoinMessage>(&String::from_utf8(bytes).expect("Error serializing the JSON"));
        match result {
            Ok(message) => {
                return Ok(Box::new(message))
            },
            Err(_) => {
                return Err(ProtocolError::InternalError) //To change the type of error
            },
        };
    }

    fn wrap(&self, instance_id: &String,) -> Result<NetMessage, String> {
        let message_data = serde_json::to_string(&self).expect("Error in serializing DecryptionShareMessage for Vec<u8>").into_bytes();
        let metadata = NetMessageMetadata::new(Channel::Gossip);
        let net_message = NetMessage::new(instance_id.clone(), metadata,message_data);
        return Ok(net_message)
    }
}


impl CoinMessage {
    pub fn new(share: CoinShare) -> Self{
        return CoinMessage::ShareMessage(share)
    }
}
