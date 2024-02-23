use serde::{Deserialize, Serialize};
use theta_network::types::message::{Channel, NetMessage, NetMessageMetadata};
use theta_schemes::interface::{DecryptionShare, Serializable};
use log::{error, info, warn};

use crate::interface::ProtocolMessageWrapper;


// To implement here a serialization that doesn't conflict with the one present at the scheme layer (based on rasn?)
// we can have a generic bytevector already in the message and serialize and deserialize here into the specific types required by the protocol.
// if we absract these steps here the protocol will not care about serializaion/deserialization details.
#[derive(Serialize, Deserialize)]
pub struct DecryptionShareMessageOut {
    share: Vec<u8>, //we want to represent the message with the field of cryptographic data already in bytes because at the scheme layer we want to use the custom Serializable trait that uses asn1
}

// pub struct DecryptionShareMessageIn {
//     share: theta_schemes::interface::DecryptionShare,
//     sender_id: u16
// }

//Here define an enum of possible messages used in the protocol
//In the case of the cipher and all the non-interactive one round protocol here we will have just one value
//for more complex protocol this is not true
#[derive(Serialize, Deserialize)]
pub enum DecryptionMessage {
    ShareMessageOut(DecryptionShareMessageOut),
    None
    // ShareMessageIn(DecryptionShareMessageIn)
}

//consider tha in protocols like frost you might have different kind of messages that needs the conversion 
//for the serialization

impl ProtocolMessageWrapper<NetMessage> for DecryptionMessage {
    fn unwrap(wrapped: NetMessage)-> Self {
        let bytes = wrapped.get_message_data().to_owned();
        let result = serde_json::from_str::<DecryptionMessage>(&String::from_utf8(bytes).expect("Error serializing the JSON"));
        match result {
            Ok(message) => {
                return message
            },
            Err(_) => {
                info!("Error serializing a decryption message")
            },
        };

        return DecryptionMessage::None //to handle better the corner case
    }

    fn wrap(&self, instance_id: &String,)->Result<NetMessage, String> {
        let message_data = serde_json::to_string(&self).expect("Error in serializing DecryptionShareMessage for Vec<u8>").into_bytes();
        let metadata = NetMessageMetadata::new(Channel::Gossip);
        let net_message = NetMessage::new(instance_id.clone(), metadata,message_data);
        return Ok(net_message)
    }
}


// impl<T> ProtocolMessage<T> for DecryptionMessage{
//     // type Message = DecryptionShareMessage;

//     fn process_message_in(&self, bytes: Vec<u8>)->Result<Box<T>, String> {
//         let result = serde_json::from_str::<DecryptionMessage>(&String::from_utf8(bytes).expect("Error serializing the JSON"));
//         match result {
//             Ok(message) => {
//                 return Ok(Box::new(message))
//             },
//             Err(_) => {
//                 return Err("Error serializing a decryption message".to_string())
//             },
//         };
//     }

//     fn process_message_out(&self, instance_id: &String,)->Result<NetMessage, String> {
//         let message_data = serde_json::to_string(&self).expect("Error in serializing DecryptionShareMessage for Vec<u8>").into_bytes();
//         // and wrap it into a NetMessage struct.
//         let metadata = NetMessageMetadata::new(&Channel::Gossip);
//         let net_message = NetMessage {
//             instance_id: instance_id.clone(),
//             metadata: metadata,
//             message_data,
//         };
//         return Ok(net_message)
//     }
// }

// impl DecryptionShareMessageIn {
//     pub fn new(sender_id: u16, message_bytes: Vec<u8>) -> Self{
//         let result = serde_json::from_str::<DecryptionMessage>(&String::from_utf8(message_bytes).expect("Error serializing the JSON"));
//         match result {
//             Ok(message) => {
//                 match message {
//                     DecryptionMessage::ShareMessageOut(out_message) => {
//                         let share = DecryptionShare::from_bytes(&out_message.share).expect("Error serializing the share from byte vector"); //handle error here
//                         return DecryptionShareMessageIn {
//                             share: share,
//                             sender_id
//                         }
//                     },
//                     _ => {
//                         todo!()
//                     }
//                 }
//             },
//             Err(_) => {
//                 info!("Error serializing a decryption message");
//             },
//         };
        
//     }
// }


///DecryptionShareMessage wraps the share needed in the protocol. 
impl DecryptionShareMessageOut {

    pub fn new(share: &theta_schemes::interface::DecryptionShare)-> Self{
        let share_bytes = share.to_bytes().expect("Error in serializing decryption share.");
        DecryptionShareMessageOut{
            share: share_bytes,
        }
    }

    pub fn get_share_bytes(&self) -> &Vec<u8>{
        return &self.share
    }    
    
    
    // Deserialize message from bytes
    // maybe here can be returned a custom error
    pub fn message_from_bytes(bytes: Vec<u8>) -> Result<DecryptionMessage, String> {
        let result = serde_json::from_str::<DecryptionMessage>(&String::from_utf8(bytes).expect("Error serializing the JSON"));
        match result {
            Ok(message) => {
                return Ok(message)
            },
            Err(_) => {
                return Err("Error serializing a decryption message".to_string())
            },
        };

        //Here handle the error from the deserialize


    }

    // pub fn to_net_message(&self, instance_id: &String,
    // ) -> NetMessage {
    //     // Serialize message to bytes. 
    //     // Here it serializes the share itself, not the message
    //     let message_data = serde_json::to_string(&self).expect("Error in serializing DecryptionShareMessage for Vec<u8>").into_bytes();
    //     // and wrap it into a NetMessage struct.
    //     let metadata = NetMessageMetadata::new(&Channel::Gossip);
    //     NetMessage {
    //         instance_id: instance_id.clone(),
    //         metadata: metadata,
    //         message_data,
    //     }
    // }
}


// match self {
//     Self::ShareMessage(message) => {
//         todo!()
//     },
//     _ => {
//         todo!()
//     }
// };