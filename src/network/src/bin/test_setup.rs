use libp2p::{floodsub, identity, PeerId};
use floodsub::Topic;
use once_cell::sync::Lazy;
use network::setup::setup::{
    listen_on,
    create_floodsub_swarm_behaviour,
    create_noise_keys,
    create_tcp_transport,
    run_event_loop};
use tokio::sync::mpsc;
use network::send::send::{send_floodsub_vecu8, message_sender};

#[tokio::main]
async fn main() {
    
    let topic: Lazy<Topic> = Lazy::new(|| Topic::new("floodsub broadcast"));

    // TODO: test get_keys / get_local_peer_id
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());

    // test get_noise_keys
    let noise_keys = create_noise_keys(id_keys);

    // test create_transport
    let transport = create_tcp_transport(noise_keys);

    // crate a Swarm to manage peers and events from floodsub protocol
    let mut swarm = create_floodsub_swarm_behaviour(
        topic.clone(), peer_id, transport).await.unwrap();

    let listen_addr = "/ip4/0.0.0.0/tcp/0";
    listen_on(&mut swarm, listen_addr.to_string()).await;

    // create channel, spawn sender
    let (tx, rx) = mpsc::unbounded_channel();

    // sends a Vec<u8> into the channel 
    let my_vec: Vec<u8> = [0b01001100u8, 0b11001100u8, 0b01101100u8].to_vec();
    tokio::spawn(message_sender(my_vec, tx));

    run_event_loop(rx, &mut swarm, topic).await;

}