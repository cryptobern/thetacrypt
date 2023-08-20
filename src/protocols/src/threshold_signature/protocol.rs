use std::collections::HashSet;
use std::sync::Arc;

use network::types::message::NetMessage;
use schemes::interface::{
    Ciphertext, Signature, SignatureShare, Serializable, ThresholdSignature, ThresholdSignatureParams, InteractiveThresholdSignature, RoundResult, ThresholdScheme, ThresholdCryptoError,
};
use schemes::keys::{PrivateKey, PublicKey};

use crate::types::{Key, ProtocolError};

pub struct ThresholdSignatureProtocol {
    key: Arc<Key>,
    message: Option<Vec<u8>>,
    label: Vec<u8>,
    chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
    chan_out: tokio::sync::mpsc::Sender<NetMessage>,
    instance_id: String,
    valid_shares: Vec<SignatureShare>,
    finished: bool,
    signature: Option<Signature>,
    instance: Option<InteractiveThresholdSignature>,
    received_share_ids: HashSet<u16>,
    round_results: Vec<RoundResult>,
    precomputed: bool
}

pub struct ThresholdSignaturePrecomputation {
    key: Arc<Key>,
    label: Vec<u8>,
    chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
    chan_out: tokio::sync::mpsc::Sender<NetMessage>,
    instance_id: String,
    finished: bool,
    instance: InteractiveThresholdSignature,
    received_share_ids: HashSet<u16>,
    round_results: Vec<RoundResult>
}

impl<'a> ThresholdSignatureProtocol {
    pub fn new(
        key: Arc<Key>,
        message: Option<&Vec<u8>>,
        label: &Vec<u8>,
        chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
        chan_out: tokio::sync::mpsc::Sender<NetMessage>,
        instance_id: String,
    ) -> Self {
        let mut instance = Option::None;
        if key.sk.get_scheme().is_interactive() {
            println!(">> Creating interactive instance");
            let mut i = InteractiveThresholdSignature::new(&key.sk);
            if i.is_err() {
                panic!("Error creating signature instance");
            }

            let mut i = i.unwrap();
            i.set_label(&label);

            instance = Option::Some(i);
        } 

        ThresholdSignatureProtocol{
            key,
            message:message.clone().cloned(),
            label:label.clone(),
            chan_in,
            chan_out,
            instance_id,
            valid_shares: Vec::new(),
            finished: false,
            signature: Option::None,
            received_share_ids: HashSet::new(),
            instance,
            round_results: Vec::new(),
            precomputed: false
        }
    }

    pub fn from_instance(
        instance: &InteractiveThresholdSignature,
        key: Arc<Key>,
        message: &Vec<u8>,
        label: &Vec<u8>,
        chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
        chan_out: tokio::sync::mpsc::Sender<NetMessage>,
        instance_id: String
    ) -> Self {
        return ThresholdSignatureProtocol{
            key,
            message:Option::Some(message.clone()),
            label:label.clone(),
            chan_in,
            chan_out,
            instance_id,
            valid_shares: Vec::new(),
            finished: false,
            signature: Option::None,
            received_share_ids: HashSet::new(),
            instance:Option::Some(instance.clone()),
            round_results: Vec::new(),
            precomputed: true
        }
    }

    pub async fn run(&mut self) -> Result<Signature, ProtocolError> {
        println!(">> PROT: instance_id: {:?} starting.", &self.instance_id);

        if(!self.precomputed) {
            self.instance.as_mut().unwrap().set_msg(&(&self.message).clone().unwrap());
        }
        
        self.on_init().await?;
        
        loop {
            match self.chan_in.recv().await {
                Some(msg) => {
                    if self.key.sk.get_scheme().is_interactive() {
                        match RoundResult::deserialize(&msg) {
                            Ok(round_result) => {
                                if self.instance.as_mut().unwrap().update(&round_result).is_err() {
                                    println!(
                                        ">> PROT: Could not process round result. Will be ignored."
                                    );
                                }

                                if self.instance.as_mut().unwrap().is_ready_for_next_round() {
                                    if self.instance.as_ref().unwrap().is_finished() {
                                        self.finished = true;
                                        let sig = self.instance.as_mut().unwrap().get_signature()?;
                                        self.signature = Some(sig);
                                        self.terminate().await?;

                                        println!(
                                            ">> PROT: Calculated signature."
                                        );
                                        return Ok(self.signature.as_ref().unwrap().clone());
                                    } 

                                    let rr = self.instance.as_mut().unwrap().do_round();
                                    self.received_share_ids.clear();
                                    self.round_results.clear();
                                    
                                    if rr.is_err() {
                                        println!(
                                            ">> PROT: Error while doing signature protocol round: {}", rr.unwrap_err().to_string()
                                        );
                                    } else {
                                        let rr = rr.unwrap();
                                        self.instance.as_mut().unwrap().update(&rr); 
                                        
                                        let message = NetMessage {
                                            instance_id: self.instance_id.clone(),
                                            message_data: rr.serialize().unwrap(),
                                            is_total_order: false
                                        };
                                        self.chan_out.send(message).await.unwrap();
                                    }
                                }
                            },
                            Err(e) => {
                                println!(
                                    ">> PROT: Could not deserialize round result. Round result will be ignored."
                                );
                                continue;
                            }
                        }
                       
                    } else {
                        match SignatureShare::deserialize(&msg) {
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
        if self.key.sk.get_scheme().is_interactive() {
            let rr = self.instance.as_mut().unwrap().do_round()?;
            self.instance.as_mut().unwrap().update(&rr);
            let message = NetMessage {
                instance_id: self.instance_id.clone(),
                message_data: rr.serialize().unwrap(),
                is_total_order: false
            };
            self.chan_out.send(message).await.unwrap();
            Ok(())
        } else {
            // compute and send decryption share
            let mut params = ThresholdSignatureParams::new();
            println!(
                ">> PROT: instance_id: {:?} computing signature share for key id:{:?}.",
                &self.instance_id,
                self.key.sk.get_id()
            );
            let share = ThresholdSignature::partial_sign(&(&self.message).clone().unwrap(), &self.label, &self.key.sk, &mut params)?;
            // println!(">> PROT: instance_id: {:?} sending decryption share with share id :{:?}.", &self.instance_id, share.get_id());
            let message = NetMessage {
                instance_id: self.instance_id.clone(),
                message_data: share.serialize().unwrap(),
                is_total_order: false
            };
            self.chan_out.send(message).await.unwrap();
            self.received_share_ids.insert(share.get_id());
            self.valid_shares.push(share);
            Ok(())
        }
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
            ThresholdSignature::verify_share(&share, &(&self.message).clone().unwrap(), &self.key.sk.get_public_key());
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
                ThresholdSignature::assemble(&self.valid_shares, &(&self.message).clone().unwrap(), &self.key.sk.get_public_key())?;
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


impl<'a> ThresholdSignaturePrecomputation {
    pub fn new(
        key: Arc<Key>,
        label: &Vec<u8>,
        chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
        chan_out: tokio::sync::mpsc::Sender<NetMessage>,
        instance_id: String,
    ) -> Self { 
        println!(">> Creating precomputation instance");
        let mut i = InteractiveThresholdSignature::new(&key.sk);
        if i.is_err() {
            panic!("Error creating precomputation instance");
        }

        let instance = i.unwrap();

        ThresholdSignaturePrecomputation{
            key,
            label:label.clone(),
            chan_in,
            chan_out,
            instance_id,
            finished: false,
            received_share_ids: HashSet::new(),
            instance,
            round_results: Vec::new()
        }
    }
    
    pub async fn run(&mut self) -> Result<InteractiveThresholdSignature, ProtocolError> {
        if self.key.sk.get_scheme() != ThresholdScheme::Frost {
            println!(">> PROT: error - trying to use precompute on scheme other than Frost");
            return Err(ProtocolError::SchemeError(ThresholdCryptoError::WrongScheme));
        }

        println!(">> PROT: instance_id: {:?} starting.", &self.instance_id);

        let rr = self.instance.do_round()?;
        let message = NetMessage {
            instance_id: self.instance_id.clone(),
            message_data: rr.serialize().unwrap(),
            is_total_order: false
        };

        self.instance.update(&rr).expect("Error processing round result");
        
        let res = self.chan_out.send(message).await;

        if res.is_ok() {
            println!(">> PROT: instance_id: {:?} sent round result.", &self.instance_id);
        } else {
            println!(">> PROT: instance_id: {:?} error sending round result.", &self.instance_id);
        }
        
        loop {
            println!("listen for messages...");
            match self.chan_in.recv().await {
                Some(msg) => {
                    println!(">> PROT: received something");
                    if self.key.sk.get_scheme() == ThresholdScheme::Frost {
                        match RoundResult::deserialize(&msg) {
                            Ok(round_result) => {
                                println!(">> PROT: Precomputation round result received");
                                if self.instance.update(&round_result).is_err() {
                                    println!(
                                        ">> PROT: Could not process round result. Will be ignored."
                                    );
                                }

                                if self.instance.is_ready_for_next_round() {
                                    println!(">> Finished precomputation");
                                   return Result::Ok(self.instance.clone()); // we have enough round results for round two - stop precomputation
                                }
                            },
                            Err(e) => {
                                println!(
                                    ">> PROT: Could not deserialize round result. Round result will be ignored."
                                );
                                continue;
                            }
                        }
                    } 
                }
                None => {
                    println!(">> PROT: Sender end unexpectedly closed. Protocol instance_id: {:?} will quit.", &self.instance_id);
                    self.terminate().await?;
                    return Err(ProtocolError::InternalError);
                }
            }
        }
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