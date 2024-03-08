use std::collections::HashSet;
use std::sync::Arc;

use chrono::Utc;
use log::{debug, error, info, warn};
use theta_events::event::Event;
use theta_network::types::message::NetMessage;
use theta_schemes::interface::{CoinShare, Serializable, ThresholdCoin};
use theta_schemes::keys::keys::PrivateKeyShare;
use theta_schemes::rand::RNG;
use tonic::async_trait;

use crate::interface::{ProtocolError, ThresholdRoundProtocol};

use super::message_types::CoinMessage;

pub struct ThresholdCoinProtocol {
    private_key: Arc<PrivateKeyShare>,
    name: Vec<u8>,
    valid_shares: Vec<CoinShare>,
    finished: bool,
    coin: Option<u8>,
    received_share_ids: HashSet<u16>,
}

impl ThresholdRoundProtocol<NetMessage> for ThresholdCoinProtocol {
    type ProtocolMessage = CoinMessage;

    fn do_round(&mut self) -> Result<Self::ProtocolMessage, ProtocolError> {
        // compute and send coin share
        let share = ThresholdCoin::create_share(
            &self.name,
            &self.private_key,
            &mut RNG::new(theta_schemes::rand::RngAlgorithm::OsRng),
        )?;

        self.received_share_ids.insert(share.get_id());
        self.valid_shares.push(share.clone());
        Ok(CoinMessage::new(share))
    }

    fn is_ready_for_next_round(&self) -> bool {
        self.valid_shares.len() >= self.private_key.get_threshold() as usize
    }

    fn is_ready_to_finalize(&self) -> bool {
        self.valid_shares.len() >= self.private_key.get_threshold() as usize
    }

    fn finalize(&mut self) -> Result<Vec<u8>, ProtocolError> {
        let assemble_result = ThresholdCoin::assemble(&self.valid_shares); 
       match assemble_result {
            Ok(result) => {
                self.coin = Some(result);
                self.finished = true;
                info!("Coin generated");
                return Ok(vec![result])
            },
            Err(scheme_error) => {
                return Err(ProtocolError::SchemeError(scheme_error))
            }
       }
    }

    fn update(&mut self, message: Self::ProtocolMessage)-> Result<(), ProtocolError> {

        match message {
            CoinMessage::ShareMessage(share) => {
                info!(
                    "Received share with share_id: {:?}.",
                    share.get_id()
                );
                if self.finished {
                    return Ok(()); //handle better this case
                }
        
                if self.received_share_ids.contains(&share.get_id()) {
                    warn!(
                        "Found share with id {:?} to be DUPLICATE. Share will be ignored.",
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
                                "Received INVALID share with id {:?}. Share will be ingored.",
                                share.get_id()
                            );
                            return Ok(()); 
                        }
                    }
                    Err(err) => {
                        warn!("Encountered error when validating share with id {:?}. Error:{:?}. Share will be ingored.", err, share.get_id());
                        return Ok(());
                    }
                }
        
                self.valid_shares.push(share);

                debug!(
                    "Valid shares: {:?}, needed: {:?}",
                    self.valid_shares.len(),
                    self.private_key.get_threshold()
                );

                return Ok(())
            },
            _ => {
                todo!() //default case
            }
        }
        
    }
}

impl ThresholdCoinProtocol {
    pub fn new(
        private_key: Arc<PrivateKeyShare>,
        name: &Vec<u8>,
    ) -> Self {
        ThresholdCoinProtocol {
            private_key,
            name: name.clone(),
            valid_shares: Vec::new(),
            finished: false,
            coin: Option::None,
            received_share_ids: HashSet::new(),
        }
    }
}
