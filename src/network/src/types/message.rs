use async_std::channel::Send;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Channel{
    Gossip,
    TOB,
    PtP {
        receiver_id: u16,
    }
}


/// NetMessageMetadata incapsulates the information for handling the transmission of the message.
/// Each message needs to specify the sender_id so that at the protocol layer it can be checked if 
/// the sender_id matched the share_id of the piece of information received.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetMessageMetadata{
    sender_id: u16,
    channel: Channel,
}

impl NetMessageMetadata{
    pub fn new(channel: Channel) -> Self {
        NetMessageMetadata {
            sender_id: 0,
            channel: channel,
        }
    }

    pub fn set_sender(&mut self, sender_id: u16){
        self.sender_id = sender_id;
    }

    pub fn get_sender(&self) -> u16 {
        return self.sender_id
    }

    pub fn get_channel(&self) -> &Channel{
        return &self.channel
    }
}


//ROSE: Every message should have the sender id. The sernder_id is authenticated by the network layer and is needed by the protocol layer to check the info 
// inside the message_data

// At an high level we want the NetMessage to contain just the instance_id, metadata, and message_data. 
// The instance_id is uzsed by the orchestration logic of the core layer to decide to which protocol execution deliver the message 
// OBSV: Can an adversary mess up with the instance ids? If we add authentication NO. 
// The metadata should be used by the network layer to decide how to send the message, to add the signature and optionally encrypt. 
// We also need a mechanism to signal if a TOB channel is available or not and in case change the bechaviour of a protocol accordingly, or 
// deny it completely.
// The message_data field is a vector of bytes with no meaning for the network layer.  
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetMessage {
    instance_id: String,
    metadata: NetMessageMetadata,
    message_data: Vec<u8>,
}

impl NetMessage {
    pub fn new(instance_id: String, metadata: NetMessageMetadata, message_data: Vec<u8>)->NetMessage{
        return NetMessage {
            instance_id,
            metadata,
            message_data,
        }
    }

    pub fn get_instace_id(&self) -> &String {
        return &self.instance_id
    }

    pub fn get_metadata(&self) -> &NetMessageMetadata{
        return &self.metadata
    }

    pub fn get_message_data(&self) -> &Vec<u8>{
        return &self.message_data
    }


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