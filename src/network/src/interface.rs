use futures::Future;
use tokio::sync::mpsc::{Receiver, Sender};

//T wil be NetMessage
use tonic::async_trait;

use crate::{config::static_net::deserialize::Config, types::message::NetMessage};

#[async_trait]
pub trait Gossip<T> {
    fn broadcast(&mut self, message: T);
    async fn deliver(&mut self) -> Option<T>;
}

#[async_trait]
pub trait TOB<T>{
    fn broadcast(message: T);
    async fn deliver(&self) -> T;
}
