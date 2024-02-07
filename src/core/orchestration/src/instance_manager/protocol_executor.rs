
use std::sync::Arc;
use theta_events::event::Event;
use theta_network::types::message::NetMessage;
use theta_protocols::interface::ThresholdRoundProtocol;
use theta_schemes::keys::keys::PrivateKeyShare;


use theta_protocols::interface::{ProtocolError, ThresholdProtocol};
use tonic::async_trait;


pub struct ThresholdProtocolExecutor<P: ThresholdRoundProtocol>{
    private_key: Arc<PrivateKeyShare>,
    chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
    chan_out: tokio::sync::mpsc::Sender<NetMessage>,
    instance_id: String,
    event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
    protocol: P,
}

impl<P: ThresholdRoundProtocol> ThresholdProtocolExecutor<P> {
    pub fn new(private_key: Arc<PrivateKeyShare>,
        chan_in: tokio::sync::mpsc::Receiver<Vec<u8>>,
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

#[async_trait]
impl<P: ThresholdRoundProtocol + std::marker::Send> ThresholdProtocol for ThresholdProtocolExecutor<P> {
    async fn run(&mut self) -> Result<Vec<u8>, ProtocolError>{
        todo!();
    }
}