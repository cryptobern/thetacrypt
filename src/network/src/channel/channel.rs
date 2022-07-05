use libp2p::gossipsub::GossipsubMessage;
use tokio::sync::mpsc::{self, UnboundedSender, UnboundedReceiver};

// creates a channel to send messages for broadcasting to the swarm.
// returns the sender to add messages to the internal channel
// and the receiver that retrieves messages from the channel to broadcast them to the network.
pub fn create_u8_chn() -> (UnboundedSender<Vec<u8>>, UnboundedReceiver<Vec<u8>>) {
    mpsc::unbounded_channel()
}

pub fn create_gossipsub_chn() -> (UnboundedSender<GossipsubMessage>, UnboundedReceiver<GossipsubMessage>) {
    mpsc::unbounded_channel()
}