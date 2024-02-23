
use theta_events::event::Event;
use theta_network::types::message::NetMessage;
use theta_protocols::interface::{ProtocolMessageWrapper, ThresholdRoundProtocol};
use chrono::Utc;

use crate::interface::ThresholdProtocol;
use theta_protocols::interface::ProtocolError;
use tonic::async_trait;
use log::{error, info};


pub struct ThresholdProtocolExecutor<P, T> where P: ThresholdRoundProtocol<T> {
    chan_in: tokio::sync::mpsc::Receiver<T>,
    chan_out: tokio::sync::mpsc::Sender<T>,
    instance_id: String,
    event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
    protocol: P ,
}

impl<P: ThresholdRoundProtocol<T>,T> ThresholdProtocolExecutor<P,T> {
    pub fn new(chan_in: tokio::sync::mpsc::Receiver<T>,
        chan_out: tokio::sync::mpsc::Sender<T>,
        instance_id: String,
        event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
        protocol: P,) -> Self{
            return Self{
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
impl<P: ThresholdRoundProtocol<T> + std::marker::Send, T: std::marker::Send> ThresholdProtocol for ThresholdProtocolExecutor<P,T> {
    async fn run(&mut self) -> Result<Vec<u8>, ProtocolError>{
        info!(
            "<{:?}>: Starting executing threshol protocol instance",
            &self.instance_id
        );

        //put here the event emitter code
        //There is no particular reason why the Events are protocol dependent 
        //eventually they can be just StartProtocol and FinishProtocol
        let event = Event::StartedInstance {
            timestamp: Utc::now(),
            instance_id: self.instance_id.clone(),
        };
        self.event_emitter_sender.send(event).await.unwrap();

        //do the initial round and handle the possible error 
        let message = self.protocol.do_round().unwrap();
        let net_message = message.wrap(&self.instance_id.clone()).unwrap();

        //send the message
        self.chan_out.send(net_message).await.unwrap();

        //start the loop for receiving
        loop {
            match self.chan_in.recv().await {
                Some(net_message) => {
                    let protocol_message = ProtocolMessageWrapper::unwrap(net_message);
                    let result = self.protocol.update(protocol_message);
                    match result {
                        Ok(_) => {
                            if self.protocol.is_ready_for_next_round() {
                                if self.protocol.is_finished(){

                                    //emitter code for signaling termination
                                    let event = Event::FinishedInstance {
                                        timestamp: Utc::now(),
                                        instance_id: self.instance_id.clone(),
                                    };
                                    self.event_emitter_sender.send(event).await.unwrap();

                                    //fetching the result 
                                    let result = self.protocol.get_result().unwrap(); //TODO: handle the error
                                    return Ok(result) 
                                }else{
                                    //go to the next rounds
                                    let message = self.protocol.do_round().unwrap();
                                    let net_message = message.wrap(&self.instance_id.clone()).unwrap();
                                    self.chan_out.send(net_message).await.unwrap();
        
                                    //update again?
                                }
                            }
                        },
                        Err(e) => {
                            return Err(e);
                        }
                    }
                },   
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

    //TODO: think if here you really need the error
    async fn terminate(&mut self)-> Result<(), ProtocolError>{
        info!("<{:?}>: Instance finished.", &self.instance_id);
        self.chan_in.close();
        Ok(())
    }
}

