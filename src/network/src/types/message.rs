use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct P2pMessage {
    pub instance_id: String,
    pub message_data: Vec<u8>
}
impl From<P2pMessage> for Vec<u8> {
    fn from(p2p_message: P2pMessage) -> Self {
        // serde_json::to_string(&p2p_message).unwrap().as_bytes().to_vec()
        serde_json::to_string(&p2p_message).expect("Error in From<P2pMessage> for Vec<u8>").into_bytes()
    }
}
impl From<Vec<u8>> for P2pMessage {
    fn from(vec: Vec<u8>) -> Self {
        serde_json::from_str::<P2pMessage>(&String::from_utf8(vec).expect("Error in From<Vec<u8>> for P2pMessage")).unwrap()
    }
}