

use crate::requests::threshold_crypto_library_server::{ThresholdCryptoLibrary,ThresholdCryptoLibraryServer};
use crate::requests::{ThresholdDecryptionRequest, ThresholdDecryptionResponse};

use cosmos_crypto::interface::{PrivateKey, Serializable, ThresholdCipherParams};
use cosmos_crypto::{interface::ThresholdCipher, dl_schemes::ciphers::sg02::{Sg02ThresholdCipher}, rand::RngAlgorithm};
use tokio::sync::mpsc::error::TryRecvError;
use {cosmos_crypto::dl_schemes::{ciphers::sg02::{Sg02DecryptionShare}, dl_groups::{ bls12381::Bls12381}}};

// A protocol must expose a single pub function run(). The caller calls this only.

pub trait Protocol: Send + Clone + 'static {
    fn run(&mut self);
}

// todo: Right now we have to .clone() all the parameters we give to the protocol, because it takes ownership.
// If I did this with references then I would have to make them all 'static (because the protocol runs on a thread)
// but I did not figure out how to make those references live long enough.
pub struct ThresholdCipherProtocol<C: ThresholdCipher> {
    sk: C::TPrivKey,
    pk: C::TPubKey,
    ciphertext: C::CT,
    chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
    chan_out: tokio::sync::mpsc::Sender<Vec<u8>>,
    instance_id: String,
    threshold: usize,
    p2p_messages: Vec<(u32, Sg02DecryptionShare<Bls12381>)>,
    valid_shares: Vec<C::TShare>,
    decrypted: bool,
    decrypted_plaintext: Vec<u8>,
}

impl<C:ThresholdCipher> ThresholdCipherProtocol<C> 
    where <C as cosmos_crypto::interface::ThresholdCipher>::TPrivKey: Send,
          <C as cosmos_crypto::interface::ThresholdCipher>::TPubKey: Send,
          <C as cosmos_crypto::interface::ThresholdCipher>::TShare: Send,
          <C as cosmos_crypto::interface::ThresholdCipher>::CT: Send
    {
    pub fn new( 
            sk: C::TPrivKey,
            pk: C::TPubKey,
            ciphertext: C::CT,
            chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
            chan_out: tokio::sync::mpsc::Sender<Vec<u8>>,
            instance_id: String,
            ) -> Self {
        ThresholdCipherProtocol{
            // threshold,
            sk,
            pk,
            ciphertext,
            chan_in,
            chan_out,
            instance_id,
            threshold: 3,
            p2p_messages: Vec::new(),
            valid_shares: Vec::new(),
            decrypted: false,
            decrypted_plaintext: Vec::new(),
        }
    }

    pub fn run(&mut self){
        println!("Threshold Cipher Protocol with instance_id: {:?} starting.", &self.instance_id);
        self.on_init();
        loop {   
            match self.chan_in.try_recv() { // todo: Change this. Use recv().await here. Otherwise no send in runnning this in a tokio task (when waiting yield control)
                Ok(share) => {
                    self.on_receive_decryption_share(C::TShare::deserialize(&share).unwrap())
                },
                Err(TryRecvError::Disconnected) => {
                    println!("Sender end unexpectedly closed. Protocol instance_id: {:?} finished.", &self.instance_id);
                },
                Err(_) => {}
            }
            if self.decrypted {
                println!("Threshold Cipher Protocol with instance_id: {:?} has decrypted the ciphertext. Plaintext is: {:?}.", &self.instance_id, &self.decrypted_plaintext);        
                self.chan_in.close();
                break;
            }
        }
        println!("Threshold Cipher Protocol with instance_id: {:?} finished.", &self.instance_id);
    }

    fn on_init(&mut self) {
        if ! C::verify_ciphertext(&self.ciphertext, &self.pk){
            println!("Threshold Cipher Protocol with instance_id: {:?} has invalid ciphertext.", &self.instance_id);
            return;
        }
        let mut params = ThresholdCipherParams::new();
        let share: C::TShare = C::partial_decrypt(&self.ciphertext, &self.sk, &mut params);
        println!("Threshold Cipher Protocol with instance_id: {:?} sending decryption share {:?}.", &self.instance_id, &self.sk.get_id());
        // todo: Check the following again. We are using try_send because it does not await (returns error if channel buffer is full).
        // But this protocol instance is the only one using this channel. So the buffer should not be full.
        self.chan_out.try_send(share.serialize().unwrap()).unwrap();
        self.valid_shares.push(share);
    }

    fn on_receive_decryption_share(&mut self, share: C::TShare) {
        if self.decrypted {
            return; 
        }
        if ! C::verify_share(&share, &self.ciphertext, &self.pk){
            return;
        }
        // todo: check duplicate share
        self.valid_shares.push(share);
        
        if self.valid_shares.len() >= self.threshold { 
            self.decrypted_plaintext = C::assemble(&self.valid_shares, &self.ciphertext);
            self.decrypted = true;
        }
    }

    fn get_plaintext(&self) -> Option<Vec<u8>> {
        if self.decrypted {
            Some(self.decrypted_plaintext.clone())
        } else {
            None
        }
    }
}
