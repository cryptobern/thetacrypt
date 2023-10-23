use std::collections::HashSet;
use std::sync::Arc;

use clap::parser::ValueSource;
use theta_network::types::message::NetMessage;
use theta_schemes::interface::{
    Ciphertext, DecryptionShare, Serializable, ThresholdCipher, ThresholdCipherParams,
};
use theta_schemes::keys::{PrivateKey, PublicKey};

use theta_orchestration::types::{Key, ProtocolError};
use crate::threshold_cipher::message_types::DecryptionShareMessage;

pub struct ThresholdCipherProtocol {
    key: Arc<Key>,
    ciphertext: Ciphertext,
    chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
    chan_out: tokio::sync::mpsc::Sender<NetMessage>,
    instance_id: String,
    valid_shares: Vec<DecryptionShare>,
    decrypted: bool,
    decrypted_plaintext: Vec<u8>,
    received_share_ids: HashSet<u16>,
}

impl ThresholdCipherProtocol {
    pub fn new(
        key: Arc<Key>,
        ciphertext: Ciphertext,
        chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
        chan_out: tokio::sync::mpsc::Sender<NetMessage>,
        instance_id: String,
    ) -> Self {
        ThresholdCipherProtocol {
            key,
            ciphertext,
            chan_in,
            chan_out,
            instance_id,
            valid_shares: Vec::new(),
            decrypted: false,
            decrypted_plaintext: Vec::new(),
            received_share_ids: HashSet::new(),
        }
    }

    pub async fn run(&mut self) -> Result<Vec<u8>, ProtocolError> {
        println!(">> PROT: instance_id: {:?} starting.", &self.instance_id);
        let valid_ctxt =
            ThresholdCipher::verify_ciphertext(&self.ciphertext, &self.key.sk.get_public_key())?;
        if !valid_ctxt {
            println!(
                ">> PROT: instance_id: {:?} found INVALID ciphertext. Protocol instance will quit.",
                &self.instance_id
            );
            self.terminate().await?;
            return Err(ProtocolError::InvalidCiphertext);
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
                            return Ok(self.decrypted_plaintext.clone());
                        }
                    } else {
                        println!(">> PROT: Received and ignored unknown message type. instance_id: {:?}", &self.instance_id);    
                    }
                }
                None => {
                    println!(">> PROT: Sender end unexpectedly closed. Protocol instance_id: {:?} will quit.", &self.instance_id);
                    self.terminate().await?;
                    return Err(ProtocolError::InternalError);
                }
            }
        }
        // todo: Currently the protocol instance will exist until it receives enough shares. Implement a timeout logic and exit the thread on expire.
    }

    async fn on_init(&mut self) -> Result<(), ProtocolError> {
        // compute and send decryption share
        let mut params = ThresholdCipherParams::new();
        println!(
            ">> PROT: instance_id: {:?} computing decryption share for key id:{:?}.",
            &self.instance_id,
            self.key.sk.get_id()
        );
        let share = ThresholdCipher::partial_decrypt(&self.ciphertext, &self.key.sk, &mut params)?;
        // println!(">> PROT: instance_id: {:?} sending decryption share with share id :{:?}.", &self.instance_id, share.get_id());
        let message = DecryptionShareMessage::to_net_message(&share, &self.instance_id);
        self.chan_out.send(message).await.unwrap();
        self.received_share_ids.insert(share.get_id());
        self.valid_shares.push(share);
        Ok(())
    }

    fn on_receive_decryption_share(&mut self, share: DecryptionShare) -> Result<(), ProtocolError> {
        println!(
            ">> PROT: instance_id: {:?} received share with share_id: {:?}.",
            &self.instance_id,
            share.get_id()
        );
        if self.decrypted {
            return Ok(());
        }

        if self.received_share_ids.contains(&share.get_id()) {
            println!(">> PROT: instance_id: {:?} found share to be DUPLICATE. share_id: {:?}. Share will be ignored.", &self.instance_id, share.get_id());
            return Ok(());
        }
        self.received_share_ids.insert(share.get_id());

        let verification_result =
            ThresholdCipher::verify_share(&share, &self.ciphertext, &self.key.sk.get_public_key());
        match verification_result {
            Ok(is_valid) => {
                if !is_valid {
                    println!(">> PROT: instance_id: {:?} received INVALID share with share_id: {:?}. Share will be ingored.", &self.instance_id, share.get_id());
                    return Ok(());
                }
            }
            Err(err) => {
                println!(">> PROT: instance_id: {:?} encountered error when validating share with share_id: {:?}. Error:{:?}. Share will be ingored.", &self.instance_id, err, share.get_id());
                return Ok(());
            }
        }

        self.valid_shares.push(share);

        println!(">> PROT: Current valid shares: {:?}", self.valid_shares.len());
        println!(">> PROT: We need still shares: {:?}", self.key.sk.get_threshold() - (self.valid_shares.len() as u16));

        if self.valid_shares.len() >= self.key.sk.get_threshold() as usize {
            self.decrypted_plaintext =
                ThresholdCipher::assemble(&self.valid_shares, &self.ciphertext)?;
            self.decrypted = true;
            println!(
                ">> PROT: instance_id: {:?} has decrypted the ciphertext.",
                &self.instance_id
            );
            return Ok(());
        }
        return Ok(());
    }

    async fn terminate(&mut self) -> Result<(), ProtocolError> {
        println!(">> PROT: instance_id: {:?} finished.", &self.instance_id);
        self.chan_in.close();
        // while let Some(share) = self.chan_in.recv().await {
        //     println!(">> PROT: instance_id: {:?} unused share with share_id: {:?}", &self.instance_id, DecryptionShare::deserialize(&share).get_id());
        // }
        Ok(())
    }
}