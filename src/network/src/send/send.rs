use floodsub::Topic;
use libp2p::{
    floodsub,
    swarm::Swarm, gossipsub::Gossipsub,
};
use libp2p::gossipsub::IdentTopic as GossibsubTopic;
use crate::setup::swarm_behaviour::FloodsubMdnsBehaviour;
use async_std::io::Error;
use std::time::Duration;
use tokio::{
    sync::mpsc::UnboundedSender,
    time,
};

// sends command line input to all nodes in the network using the floodsub protocol
pub fn send_floodsub_cmd_line(swarm: &mut Swarm<FloodsubMdnsBehaviour>, floodsub_topic: &Topic, data: String) {
    println!("SEND: {:#?}", data);
    swarm.behaviour_mut().floodsub.publish(floodsub_topic.clone(), data.as_bytes());
}

// sends a Vec<u8> to all nodes in the network using the floodsub protocol
pub fn send_floodsub_vecu8(swarm: &mut Swarm<FloodsubMdnsBehaviour>, floodsub_topic: &Topic, data: Vec<u8>) {
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

// sends msg to the channel
pub async fn message_sender(mut msg: Vec<u8>, tx: UnboundedSender<Vec<u8>>) {
    // sends repeatedly msgs to the channel
    for count in 0.. {
        msg[0] = count;
        tx.send(msg.to_vec()).unwrap();
        // waits for sending the next message
        time::sleep(Duration::from_millis(500)).await;
    }
}