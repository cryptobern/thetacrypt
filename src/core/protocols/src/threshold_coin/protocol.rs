use std::collections::HashSet;
use std::sync::Arc;

use chrono::Utc;
use log::{error, info, warn};
use theta_events::event::Event;
use theta_network::types::message::NetMessage;
use theta_schemes::interface::{CoinShare, Serializable, ThresholdCoin};
use theta_schemes::keys::keys::PrivateKeyShare;
use theta_schemes::rand::RNG;
use tonic::async_trait;

use crate::interface::{ProtocolError, ThresholdProtocol};

pub struct ThresholdCoinProtocol {
    private_key: Arc<PrivateKeyShare>,
    name: Vec<u8>,
    chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
    chan_out: tokio::sync::mpsc::Sender<NetMessage>,
    instance_id: String,
    valid_shares: Vec<CoinShare>,
    finished: bool,
    coin: Option<u8>,
    received_share_ids: HashSet<u16>,
    event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
}

#[async_trait]
impl ThresholdProtocol for ThresholdCoinProtocol {
    async fn terminate(&mut self){
        todo!()
    }
    async fn run(&mut self) -> Result<Vec<u8>, ProtocolError> {
        info!(
            "<{:?}>: Starting threshold coin instance",
            &self.instance_id
        );

        let event = Event::StartedCoinInstance {
            timestamp: Utc::now(),
            instance_id: self.instance_id.clone(),
        };
        self.event_emitter_sender.send(event).await.unwrap();

        self.on_init().await?;
        loop {
            match self.chan_in.recv().await {
                Some(share) => {
                    match CoinShare::from_bytes(&share) {
                        Ok(deserialized_share) => {
                            self.on_receive_coin_share(deserialized_share)?;
                            if self.finished {
                                self.terminate().await?;
                                let mut result = Vec::new();
                                result.push(self.coin.as_ref().unwrap().clone());

                                let event = Event::FinishedCoinInstance {
                                    timestamp: Utc::now(),
                                    instance_id: self.instance_id.clone(),
                                };
                                self.event_emitter_sender.send(event).await.unwrap();

                                return Ok(result);
                            }
                        }
                        Err(_tcerror) => {
                            info!(
                                "<{:?}>: Could not deserialize share. Share will be ignored.",
                                &self.instance_id
                            );
                            continue;
                        }
                    };
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

impl ThresholdCoinProtocol {
    pub fn new(
        private_key: Arc<PrivateKeyShare>,
        name: &Vec<u8>,
        chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
        chan_out: tokio::sync::mpsc::Sender<NetMessage>,
        event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
        instance_id: String,
    ) -> Self {
        ThresholdCoinProtocol {
            private_key,
            name: name.clone(),
            chan_in,
            chan_out,
            instance_id,
            valid_shares: Vec::new(),
            finished: false,
            coin: Option::None,
            received_share_ids: HashSet::new(),
            event_emitter_sender,
        }
    }

    async fn on_init(&mut self) -> Result<(), ProtocolError> {
        // compute and send coin share
        let share = ThresholdCoin::create_share(
            &self.name,
            &self.private_key,
            &mut RNG::new(theta_schemes::rand::RngAlgorithm::OsRng),
        )?;

        let message = NetMessage {
            instance_id: self.instance_id.clone(),
            message_data: share.to_bytes().unwrap(),
            is_total_order: false,
        };
        self.chan_out.send(message).await.unwrap();
        self.received_share_ids.insert(share.get_id());
        self.valid_shares.push(share);
        Ok(())
    }

    fn on_receive_coin_share(&mut self, share: CoinShare) -> Result<(), ProtocolError> {
        info!(
            "<{:?}>: Received share with share_id: {:?}.",
            &self.instance_id,
            share.get_id()
        );
        if self.finished {
            return Ok(());
        }

        if self.received_share_ids.contains(&share.get_id()) {
            warn!(
                "<{:?}>: Found share with id {:?} to be DUPLICATE. Share will be ignored.",
                &self.instance_id,
                share.get_id()
            );
            return Ok(());
        }
        self.received_share_ids.insert(share.get_id());

        let verification_result =
            ThresholdCoin::verify_share(&share, &self.name, &self.private_key.get_public_key());
        match verification_result {
            Ok(is_valid) => {
                if !is_valid {
                    warn!(
                        "<{:?}>: Received INVALID share with id {:?}. Share will be ingored.",
                        &self.instance_id,
                        share.get_id()
                    );
                    return Ok(());
                }
            }
            Err(err) => {
                warn!("<{:?}>: Encountered error when validating share with id {:?}. Error:{:?}. Share will be ingored.", &self.instance_id, err, share.get_id());
                return Ok(());
            }
        }

        self.valid_shares.push(share);

        if self.valid_shares.len() >= self.private_key.get_threshold() as usize {
            let coin = ThresholdCoin::assemble(&self.valid_shares)?;
            self.coin = Option::Some(coin);
            self.finished = true;
            info!("<{:?}>: Finished computing random coin.", &self.instance_id);
            return Ok(());
        }
        return Ok(());
    }

    async fn terminate(&mut self) -> Result<(), ProtocolError> {
        info!(
            "<{:?}>: Instance finished.",
            &self.private_key.get_public_key()
        );
        self.chan_in.close();
        // while let Some(share) = self.chan_in.recv().await {
        //     info!(">> PROT: instance_id: {:?} unused share with share_id: {:?}", &self.instance_id, DecryptionShare::deserialize(&share).get_id());
        // }
        Ok(())
    }
}
