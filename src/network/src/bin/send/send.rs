use libp2p::floodsub::FloodsubMessage;
use libp2p::{
    floodsub,
    swarm::Swarm, gossipsub::Gossipsub,
};
use libp2p::gossipsub::{IdentTopic as GossibsubTopic};
use floodsub::Topic;
use crate::deliver::deliver::MyBehaviour;
// use tokio::time::{sleep, Duration};
use std::{thread, time, string};
use crate::io::Error;

// sends command line input to all nodes in the network using the floodsub protocol
pub fn send_floodsub_cmd_line(swarm: &mut Swarm<MyBehaviour>, floodsub_topic: &Topic, data: String) {
    println!("SEND: {:#?}", data);
    swarm.behaviour_mut().floodsub.publish(floodsub_topic.clone(), data.as_bytes());
}

// sends a Vec<u8> to all nodes in the network using the floodsub protocol
pub fn send_floodsub_vecu8_msg(swarm: &mut Swarm<MyBehaviour>, floodsub_topic: &Topic, data: Vec<u8>) {
    println!("SEND: {:#?}", data);
    swarm.behaviour_mut().floodsub.publish(floodsub_topic.clone(), data);
}

// sends a command line input to all nodes in the network using the gossipsub protocol
pub fn send_gossipsub_msg(swarm: &mut Swarm<Gossipsub>, topic: &GossibsubTopic, data: Result<String, Error>) {
// pub fn send_gossipsub_msg(swarm: &mut Swarm<Gossipsub>, topic: &GossibsubTopic, data: Vec<u8>) {
    println!("SEND: {:#?}", data);
    if let Err(e) = swarm
        .behaviour_mut()
        .publish(topic.clone(), data.expect("Stdin not to close").as_bytes())
        // .publish(topic.clone(), data)
    {
        println!("Publish error: {:?}", e);
    }
}

pub async fn send_async(mut swarm: Swarm<MyBehaviour>, floodsub_topic: &Topic) {
// pub fn send_async(swarm: &mut Swarm<MyBehaviour>, floodsub_topic: &Topic) {
    let shares = [[0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec(),
                            [0b01001100u8, 0b01001100u8, 0b01101100u8].to_vec(),
                            [0b01101100u8, 0b11001100u8, 0b01101100u8].to_vec(),
                            [0b01001100u8, 0b11001100u8, 0b01001100u8].to_vec(),
                            [0b01101100u8, 0b11001100u8, 0b01101100u8].to_vec()];
    thread::sleep(time::Duration::from_secs(2));
    // sleep(Duration::from_secs(1)).await;
    for s in shares {
        // thread::sleep(time::Duration::from_secs(2));
        // sleep(Duration::from_secs(2)).await;
        println!("send: {:#?}", s);
        swarm.behaviour_mut().floodsub.publish(floodsub_topic.clone(), s.to_vec());
    }
}

pub trait SendMsg {
    fn send_msg(&self);
}

// default handling behaviour for a FloodsubMessage
impl SendMsg for FloodsubMessage {
    fn send_msg(&self) {
        println!("SEND floodsub msg: '{:?}'", self.data);
        // swarm.behaviour_mut().floodsub.publish(floodsub_topic.clone(), self);
    }
}