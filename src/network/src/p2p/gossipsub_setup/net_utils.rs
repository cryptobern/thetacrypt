use futures::prelude::*;
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade},
    gossipsub,
    gossipsub::{
        MessageId,
        Gossipsub,
        GossipsubEvent,
        GossipsubMessage,
        IdentTopic as GossibsubTopic,
        MessageAuthenticity,
        ValidationMode},
    identity::Keypair,
    mplex,
    noise::{AuthenticKeypair, X25519Spec, self},
    Swarm,
    swarm::{SwarmBuilder, SwarmEvent},
    tcp::TokioTcpConfig,
    Transport,
    PeerId};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    time::Duration,
};
use tokio::sync::mpsc::{Receiver, Sender};

// use crate::config::localnet_config::{config_service::*, deserialize::Config};
use crate::types::message::P2pMessage;

// Create a keypair for authenticated encryption of the transport.
pub fn create_noise_keys(keypair: &Keypair) -> AuthenticKeypair<X25519Spec> {
    noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&keypair)
        .expect("Signing libp2p-noise static DH keypair failed.")
}

// Create a tokio-based TCP transport use noise for authenticated
// encryption and Mplex for multiplexing of substreams on a TCP stream.
pub fn create_tcp_transport(noise_keys: AuthenticKeypair<X25519Spec>) -> Boxed<(PeerId, StreamMuxerBox)> {
    TokioTcpConfig::new()
        .nodelay(true)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .boxed()
}

// Create a Swarm to manage peers and events.
pub fn create_gossipsub_swarm(
    topic: &GossibsubTopic,
    id_keys: Keypair,
    transport: Boxed<(PeerId, StreamMuxerBox)>,
    local_peer_id: PeerId
) -> Swarm<Gossipsub> {
    
        // To content-address message, we can take the hash of message and use it as an ID.
    let message_id_fn = |message: &GossipsubMessage| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        MessageId::from(s.finish().to_string())
    };

    // Set a custom gossipsub
    let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
        .validation_mode(ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
        .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
        .build()
        .expect("Valid config");

    // build a gossipsub network behaviour
    let mut gossipsub: gossipsub::Gossipsub =
        gossipsub::Gossipsub::new(MessageAuthenticity::Signed(id_keys), gossipsub_config)
            .expect("Correct configuration");
            
    // subscribes to our topic
    gossipsub.subscribe(&topic).unwrap();

    // build the swarm
    SwarmBuilder::new(transport, gossipsub, local_peer_id)
        // We want the connection backgro&mut und tasks to be spawned onto the tokio runtime.
        .executor(Box::new(|fut| {
            tokio::spawn(fut);
        }))
        .build()
}

// kick off tokio::select event loop to handle events
pub async fn run_event_loop(
    swarm: &mut Swarm<Gossipsub>,
    topic: GossibsubTopic,
    mut outgoing_msg_receiver: Receiver<P2pMessage>,
    incoming_msg_sender: Sender<P2pMessage>) -> ! {
        loop {
            tokio::select! {
                // reads msg from the channel and publish it to the network
                msg = outgoing_msg_receiver.recv() => {
                    if let Some(data) = msg {
                        println!(">> NET: Sending a message");
                        swarm.behaviour_mut().publish(topic.clone(), data).expect("Publish error");
                    }
                    // todo: Terminate the loop 
                    // if msg is None (i.e., chn_out has been closed and no new message will ever be received)?
                }
                // polls swarm events
                event = swarm.select_next_some() => match event {
                    // handles (incoming) Gossipsub-Message
                    SwarmEvent::Behaviour(GossipsubEvent::Message {message, ..}) => {
                        println!(">> NET: Received a message");
                        // add incoming message to internal channel
                        incoming_msg_sender.send(message.data.into()).await.unwrap();
                    }
                    // handles NewListenAddr event
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!(">> NET: Listening on {:?}", address);
                    }
                    
                    // tells us with which endpoints we are actually connected with
                    // not so nice to display since multiple events are produced
                    // SwarmEvent::ConnectionEstablished { endpoint, .. } => {
                    //     if endpoint.is_dialer() {
                    //         println!(">> NET: Connected with {:?}", endpoint.get_remote_address());
                    //     }
                    // }
                    
                    _ => {}
                }
            }
        }
}