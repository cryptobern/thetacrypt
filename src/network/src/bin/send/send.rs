use libp2p::{
    floodsub,
    swarm::Swarm, gossipsub::Gossipsub,
};
use libp2p::gossipsub::{IdentTopic as GossibsubTopic};
use floodsub::Topic;
use crate::deliver::deliver::MyBehaviour;
use tokio::time::{sleep, Duration};
use std::{thread, time, string};
use crate::io::Error;

// sends a share to all nodes in the network using the floodsub protocol
pub fn send(swarm: &mut Swarm<MyBehaviour>, floodsub_topic: &Topic, share: Vec<u8>) {
    println!("send: {:#?}", share);
    // let my_share: Vec<u8> = [0b01001100u8, 0b01001100u8, 0b01001100u8].to_vec();
    swarm.behaviour_mut().floodsub.publish(floodsub_topic.clone(), share);
}

// pub async fn send_async(swarm: &mut Swarm<MyBehaviour>, floodsub_topic: &Topic, share: [Vec<u8>; 5]) {
pub fn send_async(swarm: &mut Swarm<MyBehaviour>, floodsub_topic: &Topic) {
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

pub fn send_gossipsub_msg(swarm: &mut Swarm<Gossipsub>, topic: &GossibsubTopic, line: Result<String, Error>) {
    if let Err(e) = swarm
        .behaviour_mut()
        .publish(topic.clone(), line.expect("Stdin not to close").as_bytes())
    {
        println!("Publish error: {:?}", e);
    }
}