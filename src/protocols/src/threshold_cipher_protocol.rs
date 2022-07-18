

use std::collections::HashSet;

use cosmos_crypto::interface::{Serializable, ThresholdCipherParams, Ciphertext, DecryptionShare, TcError};
use cosmos_crypto::keys::{PrivateKey, PublicKey};
use cosmos_crypto::{interface::ThresholdCipher, dl_schemes::ciphers::sg02::{Sg02ThresholdCipher}, rand::RngAlgorithm};
use network::types::message::P2pMessage;
use tokio::sync::mpsc::error::TryRecvError;
use {cosmos_crypto::dl_schemes::{ciphers::sg02::{Sg02DecryptionShare}, dl_groups::{ bls12381::Bls12381}}};


type InstanceId = String;

pub enum ProtocolError {
    SchemeError(TcError),
    InvalidCiphertext,
    InternalError
}

impl From<TcError> for ProtocolError{
    fn from(tc_error: TcError) -> Self {
        ProtocolError::SchemeError(tc_error)
    }
}
/*
A protocol must expose two functions, run() and terminate().
The caller should only have to call run() to start the protocol instance.

About run(): The idea is that it runs for the whole lifetime of the instance and implements the protocol logic.
In the begining it must make the necessary validity checks (e.g., valididity of ciphertext).
There is a loop(), which handles incoming shares. The loop is exited when the instance is finished.

About terminate(): It is called by the instance to cleanup any data. It must also write the resutlt
(e.g., decrypted plaintext) in result_chan_out.

Fields in ThresholdCipherProtocol:
- chan_in: The receiver end of a channel. The other end is owned by the State Manager. Network messages destined
for this instance will be received here.
- chan_out: The sender end of a channel. The other end is owned by the State Manager. Shares to other nodes
are to be sent trough this channel. The State Manager will forward it to the Network Layer.
todo: Or change the logic and give the other end directly to a Network Manager.
- result_chan_out: The sender end of a channel. The other end is owned by the State Manager. Upon termination (e.g., 
successful decryption) the instance writes the result here.
*/
pub trait Protocol: Send + Clone + 'static {
    fn run(&mut self);
    fn terminate(&mut self);
}

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
    threshold: u32,
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
                // result_chan_out: tokio::sync::mpsc::Sender<(InstanceId, Option<Vec<u8>> )>,
                instance_id: String,
              ) -> Self {
        ThresholdCipherProtocol{
            threshold: 3, //todo: fix,
            sk,
            pk,
            ciphertext,
            chan_in,
            chan_out,
            // result_chan_out,
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
            println!(">> PROT: instance_id: {:?} found INVALID ciphertext. label: {:?}. Protocol instance will quit.", &self.instance_id,&String::from_utf8(self.ciphertext.get_label()).unwrap());
            self.terminate().await;
            return Err(ProtocolError::InvalidCiphertext);
        }
        self.on_init().await?;
        loop {
           match self.chan_in.recv().await {
                Some(share) => {
                    self.on_receive_decryption_share(DecryptionShare::deserialize(&share));
                    if self.decrypted {
                        // self.terminate().await;
                        // break;
                        return Ok(self.decrypted_plaintext.clone());
                    }
                },
                None => {
                    println!(">> PROT: Sender end unexpectedly closed. Protocol instance_id: {:?} will quit.", &self.instance_id);
                    self.terminate().await;
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
            println!(">> PROT: instance_id: {:?} found share to be DUPLICATE. share_id: {:?}.", &self.instance_id, share.get_id());
            return Ok(());
        }
        self.received_share_ids.insert(share.get_id());

        if ! ThresholdCipher::verify_share(&share, &self.ciphertext, &self.pk)?{
            println!(">> PROT: instance_id: {:?} received INVALID share with share_id: {:?}.", &self.instance_id, share.get_id());
            return Ok(());
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
        while let Some(share) = self.chan_in.recv().await {
            println!(">> PROT: instance_id: {:?} unused share with share_id: {:?}", &self.instance_id, DecryptionShare::deserialize(&share).get_id());
        }
        Ok(())
    }
}
