use std::collections::HashSet;
use std::sync::Arc;

use network::types::message::P2pMessage;
use schemes::interface::{
    Ciphertext, Signature, SignatureShare, Serializable, ThresholdSignature, ThresholdSignatureParams,
};
use schemes::keys::{PrivateKey, PublicKey};

use crate::types::{Key, ProtocolError};

pub struct ThresholdSignatureProtocol {
    key: Arc<Key>,
    message: Vec<u8>,
    label: Vec<u8>,
    chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
    chan_out: tokio::sync::mpsc::Sender<P2pMessage>,
    instance_id: String,
    valid_shares: Vec<SignatureShare>,
    finished: bool,
    signature: Option<Signature>,
    received_share_ids: HashSet<u16>,
}

impl ThresholdSignatureProtocol {
    pub fn new(
        key: Arc<Key>,
        message: &Vec<u8>,
        label: &Vec<u8>,
        chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
        chan_out: tokio::sync::mpsc::Sender<P2pMessage>,
        instance_id: String,
    ) -> Self {
        ThresholdSignatureProtocol {
            key,
            message:message.clone(),
            label:label.clone(),
            chan_in,
            chan_out,
            instance_id,
            valid_shares: Vec::new(),
            finished: false,
            signature: Option::None,
            received_share_ids: HashSet::new(),
        }
    }

    pub async fn run(&mut self) -> Result<Signature, ProtocolError> {
        println!(">> PROT: instance_id: {:?} starting.", &self.instance_id);

        self.on_init().await?;
        loop {
            match self.chan_in.recv().await {
                Some(share) => {
                    match SignatureShare::deserialize(&share) {
                        Ok(deserialized_share) => {
                            self.on_receive_signature_share(deserialized_share)?;
                            if self.finished {
                                self.terminate().await?;
                                return Ok(self.signature.as_ref().unwrap().clone());
                            }
                        }
                        Err(tcerror) => {
                            println!(
                                ">> PROT: Could not deserialize share. Share will be ignored."
                            );
                            continue;
                        }
                    };
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
        let mut params = ThresholdSignatureParams::new();
        println!(
            ">> PROT: instance_id: {:?} computing signature share for key id:{:?}.",
            &self.instance_id,
            self.key.sk.get_id()
        );
        let share = ThresholdSignature::partial_sign(&self.message, &self.label, &self.key.sk, &mut params)?;
        // println!(">> PROT: instance_id: {:?} sending decryption share with share id :{:?}.", &self.instance_id, share.get_id());
        let message = P2pMessage {
            instance_id: self.instance_id.clone(),
            message_data: share.serialize().unwrap(),
        };
        self.chan_out.send(message).await.unwrap();
        self.received_share_ids.insert(share.get_id());
        self.valid_shares.push(share);
        Ok(())
    }

    fn on_receive_signature_share(&mut self, share: SignatureShare) -> Result<(), ProtocolError> {
        println!(
            ">> PROT: instance_id: {:?} received share with share_id: {:?}.",
            &self.instance_id,
            share.get_id()
        );
        if self.finished {
            return Ok(());
        }

        if self.received_share_ids.contains(&share.get_id()) {
            println!(">> PROT: instance_id: {:?} found share to be DUPLICATE. share_id: {:?}. Share will be ignored.", &self.instance_id, share.get_id());
            return Ok(());
        }
        self.received_share_ids.insert(share.get_id());

        let verification_result =
            ThresholdSignature::verify_share(&share, &self.message, &self.key.sk.get_public_key());
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

        if self.valid_shares.len() >= self.key.sk.get_threshold() as usize {
            let sig =
                ThresholdSignature::assemble(&self.valid_shares, &self.message, &self.key.sk.get_public_key())?;
            self.signature = Option::Some(sig);
            self.finished = true;
            println!(
                ">> PROT: instance_id: {:?} has issued a signature share.",
                &self.instance_id
            );
            return Ok(());
        }
        return Ok(());
    }

    async fn terminate(&mut self) -> Result<(), ProtocolError> {
        println!(">> PROT: instance_id: {:?} finished.", &self.key.sk.get_public_key());
        self.chan_in.close();
        // while let Some(share) = self.chan_in.recv().await {
        //     println!(">> PROT: instance_id: {:?} unused share with share_id: {:?}", &self.instance_id, DecryptionShare::deserialize(&share).get_id());
        // }
        Ok(())
    }
}