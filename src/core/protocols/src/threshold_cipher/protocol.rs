use std::collections::HashSet;
use std::sync::Arc;
use log::{error, info, warn};
use theta_network::types::message::NetMessage;
use theta_schemes::interface::{
    Ciphertext, DecryptionShare, Serializable, ThresholdCipher, ThresholdCipherParams
};
use theta_schemes::keys::keys::PrivateKeyShare;

use crate::interface::{ProtocolError, ThresholdRoundProtocol};
use crate::threshold_cipher::message_types::{DecryptionMessage, DecryptionShareMessageOut};

pub struct ThresholdCipherProtocol {
    private_key: Arc<PrivateKeyShare>,
    ciphertext: Ciphertext,
    instance_id: String, //We can probably give this to the executor
    valid_shares: Vec<DecryptionShare>,
    decrypted: bool,
    decrypted_plaintext: Vec<u8>,
    received_share_ids: HashSet<u16>,
}


//ROSE: see this function can be NOT async
// #[async_trait] 
impl ThresholdRoundProtocol<NetMessage> for ThresholdCipherProtocol{

    // Define the concrete type for the ProtocolMessage
    type ProtocolMessage = DecryptionMessage;

    //see if the assemble should be here or not. In the sense that it is really the final step and a local computation
    fn is_ready_for_next_round(&self) -> bool {
        return self.valid_shares.len() >= self.private_key.get_threshold() as usize
    }

    fn is_ready_to_finalize(&self) -> bool {
        return self.valid_shares.len() >= self.private_key.get_threshold() as usize
    }

    fn finalize(&mut self) -> Result<Vec<u8>, ProtocolError> {
       let assemble_result = ThresholdCipher::assemble(&self.valid_shares, &self.ciphertext); 
       match assemble_result {
            Ok(result) => {
                self.decrypted_plaintext = result;
                self.decrypted = true;
                info!("<{:?}>: Decrypted the ciphertext.", &self.instance_id);
                return Ok(self.decrypted_plaintext.clone())
            },
            Err(scheme_error) => {
                return Err(ProtocolError::SchemeError(scheme_error))
            }
       }
    }

    fn update(&mut self, message: Self::ProtocolMessage) -> Result<(), ProtocolError> {
        
        match message {
            DecryptionMessage::ShareMessageOut(share_message) => {
                let share_bytes = share_message.get_share_bytes();
                let share = DecryptionShare::from_bytes(&share_bytes).unwrap(); //TODO: handle the error

                info!(
                    "<{:?}>: Received share with id {:?}.",
                    &self.instance_id,
                    share.get_id()
                );

                //here it can be that we received a share but we already terminated the protocol
                if self.decrypted {
                    return Ok(());
                }

                //check duplicates
                if self.received_share_ids.contains(&share.get_id()) {
                    warn!(
                        "<{:?}>: Found share {:?} to be DUPLICATE. Share will be ignored.",
                        &self.instance_id,
                        share.get_id()
                    );
                    return Ok(());
                }

                //update the state
                self.received_share_ids.insert(share.get_id());

                let verification_result = ThresholdCipher::verify_share(
                    &share,
                    &self.ciphertext,
                    &self.private_key.get_public_key(),
                );
                match verification_result {
                    Ok(is_valid) => {
                        if !is_valid {
                            warn!("<{:?}>: Received INVALID share with share_id: {:?}. Share will be ingored.", &self.instance_id, share.get_id());
                            return Ok(());
                        }
                    }
                    Err(err) => {
                        warn!("<{:?}>: Encountered error when validating share with id {:?}. Error:{:?}. Share will be ingored.", &self.instance_id, err, share.get_id());
                        return Ok(());
                    }
                }

                self.valid_shares.push(share);

                info!(
                    "<{:?}>: Valid shares: {:?}, needed: {:?}",
                    &self.instance_id,
                    self.valid_shares.len(),
                    self.private_key.get_threshold()
                );

                //if there are the condition, can do the assemble
                if self.valid_shares.len() >= self.private_key.get_threshold() as usize {
                    self.decrypted_plaintext =
                        ThresholdCipher::assemble(&self.valid_shares, &self.ciphertext).unwrap(); //possible insecure unwrap  
                    self.decrypted = true;
                    info!("<{:?}>: Decrypted the ciphertext.", &self.instance_id);
                }

                return Ok(());
            },
            _ => {
                todo!()
            }
        }
    }

    fn do_round(&mut self) -> Result<Self::ProtocolMessage, ProtocolError> {

       // We know that this protocol has just one round, otherwise we need to check the current round here. 
       let valid_ctxt = ThresholdCipher::verify_ciphertext(
        &self.ciphertext,
        &self.private_key.get_public_key(),
        )?;

        if !valid_ctxt {
            error!(
                "<{:?}>: Ciphertext found INVALID. Protocol instance will quit.",
                &self.instance_id
            );
            //COMMENT_R: termination flag or something 
            //TODO: Maybe here we want to throw a scheme error?
            return Err(ProtocolError::InvalidCiphertext);
        }

        let mut params = ThresholdCipherParams::new();
        let share =
            ThresholdCipher::partial_decrypt(&self.ciphertext, &self.private_key, &mut params)?;
        let message = DecryptionShareMessageOut::new(&share);
        self.received_share_ids.insert(share.get_id());
        self.valid_shares.push(share);

        Ok(DecryptionMessage::ShareMessageOut(message))
    }

}

impl ThresholdCipherProtocol {
    pub fn new(
        private_key: Arc<PrivateKeyShare>,
        ciphertext: Ciphertext,
        instance_id: String,
    ) -> Self {
        ThresholdCipherProtocol {
            private_key,
            ciphertext,
            instance_id,
            valid_shares: Vec::new(),
            decrypted: false,
            decrypted_plaintext: Vec::new(),
            received_share_ids: HashSet::new(),
        }
    }

    // async fn on_init(&mut self) -> Result<(), ProtocolError> {
    //     // compute and send decryption share
    //     let mut params = ThresholdCipherParams::new();
    //     let share =
    //         ThresholdCipher::partial_decrypt(&self.ciphertext, &self.private_key, &mut params)?;
    //     let message = DecryptionShareMessage::to_net_message(&share, &self.instance_id);
    //     self.chan_out.send(message).await.unwrap();
    //     self.received_share_ids.insert(share.get_id());
    //     self.valid_shares.push(share);
    //     Ok(())
    // }

}
