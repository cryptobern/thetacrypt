use std::collections::HashSet;
use std::sync::Arc;

use network::types::message::NetMessage;
use schemes::interface::{
    Serializable, ThresholdSignature, ThresholdCoin, CoinShare,
};
use schemes::keys::{PrivateKey, PublicKey};
use schemes::rand::RNG;

use crate::types::{Key, ProtocolError};

pub struct ThresholdCoinProtocol {
    key: Arc<Key>,
    name: Vec<u8>,
    chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
    chan_out: tokio::sync::mpsc::Sender<NetMessage>,
    instance_id: String,
    valid_shares: Vec<CoinShare>,
    finished: bool,
    coin: Option<u8>,
    received_share_ids: HashSet<u16>,
}

impl ThresholdCoinProtocol {
    pub fn new(
        key: Arc<Key>,
        name: &Vec<u8>,
        chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
        chan_out: tokio::sync::mpsc::Sender<NetMessage>,
        instance_id: String,
    ) -> Self {
        ThresholdCoinProtocol {
            key,
            name:name.clone(),
            chan_in,
            chan_out,
            instance_id,
            valid_shares: Vec::new(),
            finished: false,
            coin: Option::None,
            received_share_ids: HashSet::new(),
        }
    }

    pub async fn run(&mut self) -> Result<u8, ProtocolError> {
        println!(">> PROT: instance_id: {:?} starting.", &self.instance_id);

        self.on_init().await?;
        loop {
            match self.chan_in.recv().await {
                Some(share) => {
                    match CoinShare::deserialize(&share) {
                        Ok(deserialized_share) => {
                            self.on_receive_coin_share(deserialized_share)?;
                            if self.finished {
                                self.terminate().await?;
                                return Ok(self.coin.as_ref().unwrap().clone());
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
        // compute and send coin share
        println!(
            ">> PROT: instance_id: {:?} computing coin share for key id:{:?}.",
            &self.instance_id,
            self.key.sk.get_id()
        );
        let share = ThresholdCoin::create_share(&self.name, &self.key.sk, &mut RNG::new(schemes::rand::RngAlgorithm::OsRng))?;
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

    fn on_receive_coin_share(&mut self, share: CoinShare) -> Result<(), ProtocolError> {
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
            ThresholdCoin::verify_share(&share, &self.name, &self.key.sk.get_public_key());
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
            let coin =
                ThresholdCoin::assemble(&self.valid_shares)?;
            self.coin = Option::Some(coin);
            self.finished = true;
            println!(
                ">> PROT: instance_id: {:?} has issued a random coin.",
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