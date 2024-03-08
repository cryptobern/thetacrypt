use serde::{Deserialize, Serialize};
use theta_network::types::message::NetMessage;
use theta_schemes::interface::SignatureShare;

use crate::interface::ProtocolMessageWrapper;


#[derive(Serialize, Deserialize)]
pub enum SignatureMessage{
    ShareMessage(SignatureShare)
}

impl ProtocolMessageWrapper<NetMessage> for SignatureMessage{
    fn unwrap(wrapped: NetMessage) -> Result<Box<Self>, crate::interface::ProtocolError> {
        todo!()
    }

    fn wrap(&self, instance_id: &String) -> Result<NetMessage, String> {
        todo!()
    }
}