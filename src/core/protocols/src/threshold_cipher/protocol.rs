use std::collections::HashSet;
use std::sync::Arc;

use chrono::Utc;
use clap::Error;
use futures::future::ok;
use log::{error, info, warn};
use theta_events::event::Event;
use theta_network::types::message::NetMessage;
use theta_schemes::interface::{
    Ciphertext, DecryptionShare, ThresholdCipher, ThresholdCipherParams,
};
use theta_schemes::keys::keys::PrivateKeyShare;
use tonic::async_trait;

use crate::interface::{ProtocolError, ThresholdProtocol, ThresholdRoundProtocol};
use crate::threshold_cipher::message_types::DecryptionShareMessage;

pub struct ThresholdCipherProtocol {
    private_key: Arc<PrivateKeyShare>,
    ciphertext: Ciphertext,
    chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
    chan_out: tokio::sync::mpsc::Sender<NetMessage>,
    instance_id: String,
    valid_shares: Vec<DecryptionShare>,
    decrypted: bool,
    decrypted_plaintext: Vec<u8>,
    received_share_ids: HashSet<u16>,
    event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
}


//ROSE: see this function can be NOT async
// #[async_trait] 
impl ThresholdRoundProtocol for ThresholdCipherProtocol{
    fn do_round(&mut self) -> Result<NetMessage, ProtocolError> {

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
            // Maybe here we want to throw a scheme error?
            return Err(ProtocolError::InvalidCiphertext);
        }

        let mut params = ThresholdCipherParams::new();
        let share =
            ThresholdCipher::partial_decrypt(&self.ciphertext, &self.private_key, &mut params)?;
        let message = DecryptionShareMessage::to_net_message(&share, &self.instance_id);
        self.received_share_ids.insert(share.get_id());
        self.valid_shares.push(share);
        Ok(message)
    }

    fn is_finished(&self) -> bool {
        return self.decrypted
    }

    //see if the assemble should be here or not. In the sense that it is really the final step and a local computation
    fn is_ready_for_next_round(&self) -> bool {
        return self.valid_shares.len() >= self.private_key.get_threshold() as usize
    }

    fn update(&mut self, message: NetMessage) -> Result<(), ProtocolError> {
        if let Some(decryption_share_message) =
            DecryptionShareMessage::try_from_bytes(&message.message_data){
                let share = decryption_share_message.share;
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
        
        } else {
            info!(
                "<{:?}>: Received and ignored unknown message type",
                &self.instance_id
            );
            return Ok(());
        }
    }

    fn get_result(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.decrypted{
            return Ok(self.decrypted_plaintext.clone());
        }
        return Err(ProtocolError::NotFinished);
    }
}

#[async_trait]
impl ThresholdProtocol for ThresholdCipherProtocol {
    async fn terminate(&mut self){
        todo!()
    }
    async fn run(&mut self) -> Result<Vec<u8>, ProtocolError> {
        info!(
            "<{:?}>: Starting threshold cipher instance",
            &self.instance_id
        );

        //There is no particular reason why the Events are protocol dependent 
        //eventually they can be just StartProtocol and FinishProtocol
        let event = Event::StartedDecryptionInstance {
            timestamp: Utc::now(),
            instance_id: self.instance_id.clone(),
        };
        self.event_emitter_sender.send(event).await.unwrap();

        let valid_ctxt = ThresholdCipher::verify_ciphertext(
            &self.ciphertext,
            &self.private_key.get_public_key(),
        )?;
        if !valid_ctxt {
            error!(
                "<{:?}>: Ciphertext found INVALID. Protocol instance will quit.",
                &self.instance_id
            );
            self.terminate().await?;
            return Err(ProtocolError::InvalidCiphertext); //understand how to handle the errors. 
        }
        self.on_init().await?;
        loop {
            match self.chan_in.recv().await {
                Some(message_data) => {
                    if let Some(decryption_share_message) =
                        DecryptionShareMessage::try_from_bytes(&message_data)
                    {
                        self.on_receive_decryption_share(decryption_share_message.share)?;
                        if self.decrypted {
                            self.terminate().await?;

                            let event = Event::FinishedDecryptionInstance {
                                timestamp: Utc::now(),
                                instance_id: self.instance_id.clone(),
                            };
                            self.event_emitter_sender.send(event).await.unwrap();

                            return Ok(self.decrypted_plaintext.clone());
                        }
                    } else {
                        info!(
                            "<{:?}>: Received and ignored unknown message type",
                            &self.instance_id
                        );
                    }
                }
                None => {
                    error!(
                        "<{:?}>: Sender end unexpectedly closed. Protocol instance will quit.",
                        &self.instance_id
                    );
                    self.terminate().await?;
                    return Err(ProtocolError::InternalError);
                }
            }
        }
        // todo: Currently the protocol instance will exist until it receives enough shares. Implement a timeout logic and exit the thread on expire.
    }
}

impl ThresholdCipherProtocol {
    pub fn new(
        private_key: Arc<PrivateKeyShare>,
        ciphertext: Ciphertext,
        chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
        chan_out: tokio::sync::mpsc::Sender<NetMessage>,
        event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
        instance_id: String,
    ) -> Self {
        ThresholdCipherProtocol {
            private_key,
            ciphertext,
            chan_in,
            chan_out,
            instance_id,
            valid_shares: Vec::new(),
            decrypted: false,
            decrypted_plaintext: Vec::new(),
            received_share_ids: HashSet::new(),
            event_emitter_sender,
        }
    }

    async fn on_init(&mut self) -> Result<(), ProtocolError> {
        // compute and send decryption share
        let mut params = ThresholdCipherParams::new();
        let share =
            ThresholdCipher::partial_decrypt(&self.ciphertext, &self.private_key, &mut params)?;
        let message = DecryptionShareMessage::to_net_message(&share, &self.instance_id);
        self.chan_out.send(message).await.unwrap();
        self.received_share_ids.insert(share.get_id());
        self.valid_shares.push(share);
        Ok(())
    }

    fn on_receive_decryption_share(&mut self, share: DecryptionShare) -> Result<(), ProtocolError> {
        info!(
            "<{:?}>: Received share with id {:?}.",
            &self.instance_id,
            share.get_id()
        );
        if self.decrypted {
            return Ok(());
        }

        if self.received_share_ids.contains(&share.get_id()) {
            warn!(
                "<{:?}>: Found share {:?} to be DUPLICATE. Share will be ignored.",
                &self.instance_id,
                share.get_id()
            );
            return Ok(());
        }
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

        if self.valid_shares.len() >= self.private_key.get_threshold() as usize {
            self.decrypted_plaintext =
                ThresholdCipher::assemble(&self.valid_shares, &self.ciphertext)?;
            self.decrypted = true;
            info!("<{:?}>: Decrypted the ciphertext.", &self.instance_id);
            return Ok(());
        }
        return Ok(());
    }

    async fn terminate(&mut self) -> Result<(), ProtocolError> {
        info!("<{:?}>: Instance finished.", &self.instance_id);
        self.chan_in.close();
        // while let Some(share) = self.chan_in.recv().await {
        //     info!(">> PROT: instance_id: {:?} unused share with share_id: {:?}", &self.instance_id, DecryptionShare::deserialize(&share).get_id());
        // }
        Ok(())
    }
}
