use std::fmt::Debug;

use chrono::Utc;
use theta_events::event::Event;
use theta_protocols::interface::{ProtocolMessageWrapper, ThresholdRoundProtocol};
use tokio::sync::mpsc::error::SendError;

use crate::interface::ThresholdProtocol;
use log::{error, info};
use theta_protocols::interface::ProtocolError;
use tonic::async_trait;

pub struct ThresholdProtocolExecutor<P, T>
where
    P: ThresholdRoundProtocol<T>,
{
    chan_in: tokio::sync::mpsc::Receiver<T>,
    chan_out: tokio::sync::mpsc::Sender<T>,
    instance_id: String,
    event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
    protocol: P,
}

impl<P: ThresholdRoundProtocol<T>, T> ThresholdProtocolExecutor<P, T> {
    pub fn new(
        chan_in: tokio::sync::mpsc::Receiver<T>,
        chan_out: tokio::sync::mpsc::Sender<T>,
        instance_id: String,
        event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
        protocol: P,
    ) -> Self {
        return Self {
            chan_in,
            chan_out,
            instance_id,
            event_emitter_sender,
            protocol,
        };
    }
}

//TODO: Handle trowing the errors
#[async_trait]
impl<P: ThresholdRoundProtocol<T> + std::marker::Send, T: std::marker::Send + Debug>
    ThresholdProtocol for ThresholdProtocolExecutor<P, T>
{
    async fn run(&mut self) -> Result<Vec<u8>, ProtocolError> {
        info!(
            "<{:?}>: Starting executing threshold protocol instance",
            &self.instance_id
        );

        //put here the event emitter code
        //There is no particular reason why the Events are protocol dependent
        //changed in just StartProtocol and FinishProtocol
        let event = Event::StartedInstance {
            timestamp: Utc::now(),
            instance_id: self.instance_id.clone(),
        };
        self.event_emitter_sender.send(event).await.unwrap();

        //do the initial round and handle the possible error
        let message_result = self.protocol.do_round();
        match message_result {
            Ok(message) => {
                if !message.is_default() {
                    let net_message = message.wrap(&self.instance_id.clone()).unwrap();
                    self.chan_out.send(net_message).await.unwrap();
                }
            }
            Err(e) => {
                let error_message = format!("Error during initial round: {:?}", e);
                error!("{}", error_message);
                let event = Event::FailedInstance {
                    timestamp: Utc::now(),
                    instance_id: self.instance_id.clone(),
                    error_message: error_message.to_string(),
                };
                self.event_emitter_sender.send(event).await.unwrap();
                return Err(e);
            }
        }

        //start the loop for receiving
        loop {
            match self.chan_in.recv().await {
                Some(net_message) => {
                    let protocol_message: <P as ThresholdRoundProtocol<T>>::ProtocolMessage =
                        *ProtocolMessageWrapper::unwrap(net_message).unwrap(); // handle the error
                    let result = self.protocol.update(protocol_message.into());
                    match result {
                        Ok(_) => {
                            if self.protocol.is_ready_to_finalize() {
                                let result = self.protocol.finalize(); //handle the error

                                match result {
                                    Ok(value) => {

                                        //emitter code for signaling termination
                                        let event = Event::FinishedInstance {
                                            timestamp: Utc::now(),
                                            instance_id: self.instance_id.clone(),
                                        };
                                        self.event_emitter_sender.send(event).await.unwrap();

                                        info!(
                                            "<{:?}>: Finished executing threshold protocol instance",
                                            &self.instance_id
                                        );

                                        return Ok(value)
                                    }
                                    Err(prot_err) => {
                                        let error_message = format!("Error during finalization: {:?}", prot_err);
                                        let event = Event::FailedInstance {
                                            timestamp: Utc::now(),
                                            instance_id: self.instance_id.clone(),
                                            error_message: error_message.to_string(),
                                        };
                                        self.event_emitter_sender.send(event).await.unwrap();
                                        error!(
                                            "<{:?}>: {:?}",
                                            &self.instance_id, prot_err
                                        );
                                        return Err(prot_err);
                                    }
                                }
                            } else {
                                if self.protocol.is_ready_for_next_round() {
                                    //go to the next rounds
                                    let message_result = self.protocol.do_round();
                                    match message_result {
                                        Ok(message) => {
                                            if !message.is_default() {
                                                let net_message = message.wrap(&self.instance_id.clone()).unwrap();
                                                self.chan_out.send(net_message).await.unwrap();
                                            }
                                        }
                                        Err(e) => {
                                            let error_message = format!("Error during round: {:?}", e);
                                            error!("{}", error_message);
                                            let event = Event::FailedInstance {
                                                timestamp: Utc::now(),
                                                instance_id: self.instance_id.clone(),
                                                error_message: error_message.to_string(),
                                            };
                                            self.event_emitter_sender.send(event).await.unwrap();
                                            return Err(e);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            let error_message = format!("Error during update: {:?}", e);
                            error!("{}", error_message);
                            let event = Event::FailedInstance {
                                timestamp: Utc::now(),
                                instance_id: self.instance_id.clone(),
                                error_message: error_message.to_string(),
                            };
                            self.event_emitter_sender.send(event).await.unwrap();
                            return Err(e);
                        }
                    }
                }
                None => {
                    error!(
                        "<{:?}>: Sender end unexpectedly closed. Protocol instance will quit.",
                        &self.instance_id
                    );
                    let error_message = format!("Channel for receiving closed.");
                            error!("{}", error_message);
                            let event = Event::FailedInstance {
                                timestamp: Utc::now(),
                                instance_id: self.instance_id.clone(),
                                error_message: error_message.to_string(),
                            };
                            self.event_emitter_sender.send(event).await.unwrap();
                    self.chan_in.close();
                    return Err(ProtocolError::NotFinished);
                }
            }
        }
    }
}
