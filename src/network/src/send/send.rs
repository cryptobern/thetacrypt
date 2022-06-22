use tokio::sync::mpsc::{self, UnboundedSender, UnboundedReceiver};

// creates a channel to send messages for broadcasting by the swarm
pub fn create_channel() -> (UnboundedSender<Vec<u8>>, UnboundedReceiver<Vec<u8>>) {
    mpsc::unbounded_channel()
}