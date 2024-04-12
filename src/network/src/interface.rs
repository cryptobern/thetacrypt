use tonic::async_trait;

//T wil be NetMessage
#[async_trait]
pub trait Gossip<T> {
    fn broadcast(&mut self, message: T);
    async fn deliver(&mut self) -> Option<T>;
}

#[async_trait]
pub trait TOB<T>{
    fn broadcast(&mut self, message: T);
    async fn deliver(&self) -> Option<T>;
}

/// TOBComponentEmpty implements the TOB interface to provide rust with a concrete type but it is meant to use when a TOB channel is unavailable
/// The generic T allows to not specify in the interface the type of messages that the channels will handle
pub struct TOBComponentEmpty<T>{
     _message: T
}

#[async_trait]
impl<T: std::marker::Sync> TOB<T> for TOBComponentEmpty<T>{
    fn broadcast(&mut self,_message:T) {
        unimplemented!()
    }

    async fn deliver(&self)->Option<T>{
        unimplemented!()
    }
}

#[async_trait]
pub trait NetworkService {
    fn listen_on(&self, port: i32);
}
