use floodsub::Topic;
use libp2p::{
    floodsub,
    swarm::Swarm, gossipsub::Gossipsub,
};
use libp2p::gossipsub::IdentTopic as GossibsubTopic;
use crate::deliver::deliver::MyBehaviour;
use crate::io::Error;
use std::time::Duration;
use tokio::{
    sync::mpsc::UnboundedSender,
    time,
};

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

// for channel testing
pub async fn message_sender(msg: &'static str, tx: UnboundedSender<String>) {
    for count in 0.. {
        let message = format!("{msg}{count}");
        tx.send(message).unwrap();

        time::sleep(Duration::from_millis(500)).await;
    }
}