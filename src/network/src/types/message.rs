use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct NetMessage {
    pub instance_id: String,
    pub is_total_order: bool,
    pub message_data: Vec<u8>,
}
impl From<NetMessage> for Vec<u8> {
    fn from(p2p_message: NetMessage) -> Self {
        // serde_json::to_string(&p2p_message).unwrap().as_bytes().to_vec()
        serde_json::to_string(&p2p_message).expect("Error in From<NetMessage> for Vec<u8>").into_bytes()
    }
}
impl From<Vec<u8>> for NetMessage {
    fn from(vec: Vec<u8>) -> Self {
        serde_json::from_str::<NetMessage>(&String::from_utf8(vec).expect("Error in From<Vec<u8>> for NetMessage")).unwrap()
    }
}