
use std::sync::Arc;
use theta_events::event::Event;
use theta_network::types::message::NetMessage;
use theta_protocols::{interface::ThresholdRoundProtocol, threshold_cipher::protocol};
use theta_schemes::keys::keys::PrivateKeyShare;


use theta_protocols::interface::{ProtocolError, ThresholdProtocol};
use tonic::async_trait;
use log::{error, info, warn};


pub struct ThresholdProtocolExecutor<P: ThresholdRoundProtocol>{
    private_key: Arc<PrivateKeyShare>,
    chan_in: tokio::sync::mpsc::Receiver<NetMessage>,
    chan_out: tokio::sync::mpsc::Sender<NetMessage>,
    instance_id: String,
    event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
    protocol: P,
}

impl<P: ThresholdRoundProtocol> ThresholdProtocolExecutor<P> {
    pub fn new(private_key: Arc<PrivateKeyShare>,
        chan_in: tokio::sync::mpsc::Receiver<NetMessage>,
        chan_out: tokio::sync::mpsc::Sender<NetMessage>,
        instance_id: String,
        event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
        protocol: P,) -> Self{
            return Self{
                private_key,
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
impl<P: ThresholdRoundProtocol + std::marker::Send> ThresholdProtocol for ThresholdProtocolExecutor<P> {
    async fn run(&mut self) -> Result<Vec<u8>, ProtocolError>{
        info!(
            "<{:?}>: Starting executing threshol protocol instance",
            &self.instance_id
        );

        //put here the event emitter code

        //do the initial round 
        let net_message = self.protocol.do_round().unwrap();

        //send the message
        self.chan_out.send(net_message).await.unwrap();

        //start the loop for receiving
        loop {
            match self.chan_in.recv().await {
                Some(message_data) => {
                    self.protocol.update(message_data);
                    if self.protocol.is_ready_for_next_round() {
                        if self.protocol.is_finished(){
                            //get restult
                        }else{
                            //go to the next rounds
                            let net_message = self.protocol.do_round().unwrap();
                            self.chan_out.send(net_message).await.unwrap();

                            //update again?
                        }
                    }
                }
                None => {
                    error!(
                        "<{:?}>: Sender end unexpectedly closed. Protocol instance will quit.",
                        &self.instance_id
                    );
                    self.terminate().await;
                    return Err(ProtocolError::InternalError);
                }
            }
        }


    }

    //TODO: close the channel 
    async fn terminate(&mut self){
        todo!()
    }
}

