

use crate::requests::threshold_protocol_server::{ThresholdProtocol,ThresholdProtocolServer};
use crate::requests::{ThresholdDecryptionRequest, ThresholdDecryptionResponse};

use cosmos_crypto::{interface::ThresholdCipher, dl_schemes::ciphers::sg02::{Sg02ThresholdCipher}, rand::RngAlgorithm};
use {cosmos_crypto::dl_schemes::{ciphers::sg02::{Sg02DecryptionShare}, dl_groups::{ bls12381::Bls12381}}};

// A protocol must expose a single pub function run(). The caller calls this only.
pub trait Protocol {
    fn run(&mut self);
}

// todo: Right now we have to .clone() all the parameters we give to the protocol, because it takes ownership.
// If I did this with references then I would have to make them all 'static (because the protocol runs on a thread)
// but I did not figure out how to make those references live long enough.
pub struct ThresholdCipherProtocol<C: ThresholdCipher> {
    threshold: usize,
    pk: C::TPubKey,
    sk: C::TPrivKey,
    ciphertext: C::CT,
    p2p_messages: Vec<(u32, Sg02DecryptionShare<Bls12381>)>,
    valid_shares: Vec<C::TShare>,
    decrypted: bool,
    decrypted_plaintext: Vec<u8>,
    chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
    chan_out: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl<C:ThresholdCipher> ThresholdCipherProtocol<C> {
    pub fn new(
            threshold: usize,
            pk: C::TPubKey,
            sk: C::TPrivKey,
            ciphertext: C::CT,
            chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
            chan_out: tokio::sync::mpsc::Sender<Vec<u8>>,
            ) -> Self {
        ThresholdCipherProtocol{
            threshold,
            pk,
            sk,
            ciphertext,
            chan_in,
            chan_out,
            p2p_messages: Vec::new(),
            valid_shares: Vec::new(),
            decrypted: false,
            decrypted_plaintext: Vec::new(),
        }
    }

    pub fn run(&mut self){
        self.on_init();
        println!("Thread done.")
    }

    fn on_init(&mut self) {
        if ! C::verify_ciphertext(&self.ciphertext, &self.pk){
            return;
        }
        // let mut params = Sg02Params::new(RngAlgorithm::MarsagliaZaman); // todo: Create a trait function in ThresholdCipher so you can call ThresholdCipher::getParams() here
        // let share: C::TShare = C::partial_decrypt(&self.ctxt, &self.sk, C::TParams::new());
        // self.valid_shares.push(share);
        // todo: actually send the share. Over a channel to the p2p layer?
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
        
        if self.valid_shares.len() >= self.threshold as usize { 
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
