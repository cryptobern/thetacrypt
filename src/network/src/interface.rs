//T wil be NetMessage
use tonic::async_trait;

#[async_trait]
pub trait Gossip: Send {
    type T;
    fn broadcast(&mut self, message: Self::T) -> Result<(), String>;
    async fn deliver(&mut self) -> Option<Self::T>;
    async fn init(&mut self) -> Result<(), String>;
}

#[async_trait]
pub trait TOB: Send + Sync{
    type T;
    fn broadcast(&mut self, message: Self::T);
    async fn deliver(&self) -> Self::T;
}

#[async_trait]
pub trait NetworkService {
    fn listen_on(&self, port: i32);
}