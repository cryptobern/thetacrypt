use theta_network::types::message::NetMessage;
use theta_schemes::interface::{DecryptionShare, Serializable};

pub struct DecryptionShareMessage {
    pub share: theta_schemes::interface::DecryptionShare,
}

impl DecryptionShareMessage {
    // Deserialize message from bytes
    pub fn try_from_bytes(bytes: &Vec<u8>) -> Option<DecryptionShareMessage> {
        match DecryptionShare::from_bytes(bytes) {
            Ok(share) => Some(DecryptionShareMessage { share }),
            Err(_tc_error) => None,
        }
    }

    pub fn to_net_message(
        share: &theta_schemes::interface::DecryptionShare,
        instance_id: &String,
    ) -> NetMessage {
        // Serialize message to bytes
        let message_data: Vec<u8> = share
            .to_bytes()
            .expect("Error in serializing decryption share.");
        // and wrap it into a NetMessage struct.
        NetMessage {
            instance_id: instance_id.clone(),
            is_total_order: false,
            message_data,
        }
    }
}
