use std::collections::HashSet;

use crate::protocol::ProtocolError;
use schemes::interface::{ThresholdCipherParams, Ciphertext, DecryptionShare, ThresholdCipher};
use schemes::keys::{PrivateKey, PublicKey};
use network::types::message::P2pMessage;



// todo: Right now we have to .clone() all the parameters we give to the protocol, because it takes ownership.
// If I did this with references then I would have to make them all 'static (because the protocol runs on a thread)
// but I did not figure out how to make those references live long enough.
pub struct ThresholdCipherProtocol {
    sk: PrivateKey,
    pk: PublicKey,
    ciphertext: Ciphertext,
    chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
    chan_out: tokio::sync::mpsc::Sender<P2pMessage>,
    // result_chan_out: tokio::sync::mpsc::Sender<(InstanceId, Option<Vec<u8>>)>,
    instance_id: String,
    threshold: u16,
    valid_shares: Vec<DecryptionShare>,
    decrypted: bool,
    decrypted_plaintext: Vec<u8>,
    received_share_ids: HashSet<u16>,
}

impl ThresholdCipherProtocol {
    pub fn new( sk: PrivateKey,
                pk: PublicKey,
                ciphertext: Ciphertext,
                chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
                chan_out: tokio::sync::mpsc::Sender<P2pMessage>,
                instance_id: String,
              ) -> Self {
        ThresholdCipherProtocol{
            threshold: sk.get_threshold(),
            sk,
            pk,
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

    pub async fn run(&mut self) -> Result<Vec<u8>, ProtocolError>{
        println!(">> PROT: instance_id: {:?} starting.", &self.instance_id);
        if ! ThresholdCipher::verify_ciphertext(&self.ciphertext, &self.pk)?{
            println!(">> PROT: instance_id: {:?} found INVALID ciphertext. Protocol instance will quit.", &self.instance_id );
            self.terminate().await?;
            return Err(ProtocolError::InvalidCiphertext);
        }
        self.on_init().await?;
        loop {
           match self.chan_in.recv().await {
                Some(share) => {
                    match DecryptionShare::deserialize(&share){
                        Ok(deserialized_share) => {
                            self.on_receive_decryption_share(deserialized_share)?;
                            if self.decrypted {
                                self.terminate().await?;
                                return Ok(self.decrypted_plaintext.clone());
                            }
                        },
                        Err(tcerror) => {
                            println!(">> PROT: Could not deserialize share. Share will be ignored.");
                            continue;        
                        },
                    };
                },
                None => {
                    println!(">> PROT: Sender end unexpectedly closed. Protocol instance_id: {:?} will quit.", &self.instance_id);
                    self.terminate().await?;
                    return Err(ProtocolError::InternalError)
                }
            }
        }
        // todo: Currently the protocol instance will exist until it receives enough shares. Implement a timeout logic and exit the thread on expire.   
    }

    async fn on_init(&mut self) -> Result<(), ProtocolError> {
        // compute and send decryption share
        let mut params = ThresholdCipherParams::new();
        println!(">> PROT: instance_id: {:?} computing decryption share for key id:{:?}.", &self.instance_id, self.sk.get_id());
        let share = ThresholdCipher::partial_decrypt(&self.ciphertext, &self.sk, &mut params)?;
        // println!(">> PROT: instance_id: {:?} sending decryption share with share id :{:?}.", &self.instance_id, share.get_id());
        let message = P2pMessage{
            instance_id: self.instance_id.clone(),
            message_data: share.serialize().unwrap(),
        };
        self.chan_out.send(message).await.unwrap();
        self.received_share_ids.insert(share.get_id());
        self.valid_shares.push(share);
        Ok(())
    }

    fn on_receive_decryption_share(&mut self, share: DecryptionShare) -> Result<(), ProtocolError> {
        println!(">> PROT: instance_id: {:?} received share with share_id: {:?}.", &self.instance_id, share.get_id());
        if self.decrypted {
            return Ok(());
        }

        if self.received_share_ids.contains(&share.get_id()){
            println!(">> PROT: instance_id: {:?} found share to be DUPLICATE. share_id: {:?}. Share will be ignored.", &self.instance_id, share.get_id());
            return Ok(());
        }
        self.received_share_ids.insert(share.get_id());

        let verification_result = ThresholdCipher::verify_share(&share, &self.ciphertext, &self.pk);
        match verification_result{
            Ok(is_valid) => {
                if ! is_valid {
                    println!(">> PROT: instance_id: {:?} received INVALID share with share_id: {:?}. Share will be ingored.", &self.instance_id, share.get_id());
                    return Ok(());
                }
            },
            Err(err) => {
                println!(">> PROT: instance_id: {:?} encountered error when validating share with share_id: {:?}. Error:{:?}. Share will be ingored.", &self.instance_id, err, share.get_id());
                return Ok(());
            },
        }
        
        self.valid_shares.push(share);
        
        if self.valid_shares.len() >= self.threshold as usize { 
            self.decrypted_plaintext = ThresholdCipher::assemble(&self.valid_shares, &self.ciphertext)?;
            self.decrypted = true;
            println!(">> PROT: instance_id: {:?} has decrypted the ciphertext. Plaintext is: {:?}.", &self.instance_id, String::from_utf8(self.decrypted_plaintext.clone()).unwrap());
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
