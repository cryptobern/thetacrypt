

use std::collections::HashSet;

use crate::requests::threshold_crypto_library_server::{ThresholdCryptoLibrary,ThresholdCryptoLibraryServer};
use crate::requests::{ThresholdDecryptionRequest, ThresholdDecryptionResponse};

use cosmos_crypto::interface::{PrivateKey, Serializable, ThresholdCipherParams, Share};
use cosmos_crypto::{interface::ThresholdCipher, dl_schemes::ciphers::sg02::{Sg02ThresholdCipher}, rand::RngAlgorithm};
use tokio::sync::mpsc::error::TryRecvError;
use {cosmos_crypto::dl_schemes::{ciphers::sg02::{Sg02DecryptionShare}, dl_groups::{ bls12381::Bls12381}}};


// A protocol must expose two functions, run() and terminate().
// The caller should only have to call run() to start the protocol instance.
// terminate() is called by the instance to cleanup any data.
//
// About run(): The idea is that it runs for the whole lifetime of the instance.
// In the begining it calls on_init(), for the stuff the instance must do upon starting.
// Then there is a loop(), which handles incoming shares. The loop is broken when instance is done.
pub trait Protocol: Send + Clone + 'static {
    fn run(&mut self);
    fn terminate(&mut self);
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
    threshold: u32,
    valid_shares: Vec<C::TShare>,
    decrypted: bool,
    decrypted_plaintext: Vec<u8>,
    received_share_ids: HashSet<u32>,
}

impl<C:ThresholdCipher> ThresholdCipherProtocol<C> 
    where <C as cosmos_crypto::interface::ThresholdCipher>::TPrivKey: Send + 'static,
          <C as cosmos_crypto::interface::ThresholdCipher>::TPubKey: Send + 'static,
          <C as cosmos_crypto::interface::ThresholdCipher>::TShare: Send + 'static,
          <C as cosmos_crypto::interface::ThresholdCipher>::CT: Send + 'static
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

    pub async fn run(&mut self){
        println!(">> CP: instance_id: {:?} starting.", &self.instance_id);
        self.on_init().await;
        loop {
            let next_msg = self.chan_in.recv().await;
            match next_msg { 
                Some(share) => {
                    self.on_receive_decryption_share(C::TShare::deserialize(&share).unwrap());
                    if self.decrypted {
                        println!(">> CP: instance_id: {:?} has decrypted the ciphertext. Plaintext is: {:?}.", &self.instance_id, String::from_utf8(self.decrypted_plaintext.clone()).unwrap());
                        self.terminate();
                        break;
                    }
                },
                None => {
                    println!(">> CP: Sender end unexpectedly closed. Protocol instance_id: {:?} finished.", &self.instance_id);
                    self.terminate();
                    break;
                }
            }
        }
        // todo: Currently the protocol instance will exist until it receives enough shares.
        // Maybe implement a timeout and exist the thread if it expires.   
    }

    async fn on_init(&mut self) {
        if ! C::verify_ciphertext(&self.ciphertext, &self.pk){
            println!(">> CP: instance_id: {:?} has INVALID ciphertext.", &self.instance_id);
            return;
        }
        let mut params = ThresholdCipherParams::new();
        
        println!(">> CP: instance_id: {:?} computing decryption share for key id:{:?}.", &self.instance_id, self.sk.get_id());
        let share: C::TShare = C::partial_decrypt(&self.ciphertext, &self.sk, &mut params);
        println!(">> CP: instance_id: {:?} sending decryption share with share id :{:?}.", &self.instance_id, share.get_id());
        self.chan_out.send(share.serialize().unwrap()).await.unwrap();
        self.valid_shares.push(share);
    }

    fn on_receive_decryption_share(&mut self, share: C::TShare) {
        println!(">> CP: instance_id: {:?} received share with share_id: {:?}.", &self.instance_id, share.get_id());
        if self.decrypted {
            return; 
        }

        if self.received_share_ids.contains(&share.get_id()){
            println!(">> CP: instance_id: {:?} received DUPLICATE share with share_id: {:?}.", &self.instance_id, share.get_id());
            return;
        }
        self.received_share_ids.insert(share.get_id());

        if ! C::verify_share(&share, &self.ciphertext, &self.pk){
            println!(">> CP: instance_id: {:?} received INVALID share with share_id: {:?}.", &self.instance_id, share.get_id());
            return;
        }
        self.valid_shares.push(share);
        
        if self.valid_shares.len() >= self.threshold as usize { 
            self.decrypted_plaintext = C::assemble(&self.valid_shares, &self.ciphertext);
            self.decrypted = true;
        }
    }

    fn terminate(&mut self){
        println!(">> CP: instance_id: {:?} finished.", &self.instance_id);
        self.chan_in.close();
    }
}
