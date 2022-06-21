use libp2p::{
    floodsub::{Floodsub, FloodsubEvent},
    mdns::{Mdns, MdnsEvent},
    NetworkBehaviour,
    swarm::NetworkBehaviourEventProcess,
};
use crate::deliver::deliver::HandleMsg;

#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
pub struct FloodsubMdnsBehaviour {
    pub floodsub: Floodsub,
    pub mdns: Mdns, // automatically discovers other libp2p nodes on the local network.
}

impl NetworkBehaviourEventProcess<FloodsubEvent> for FloodsubMdnsBehaviour {
    // Called when `floodsub` produces an event.
    fn inject_event(&mut self, message: FloodsubEvent) {
        if let FloodsubEvent::Message(message) = message {
            message.handle_msg();
        }
    }
}

impl NetworkBehaviourEventProcess<MdnsEvent> for FloodsubMdnsBehaviour {
    // Called when `mdns` produces an event.
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(list) => {
                for (peer, _) in list {
                    self.floodsub.add_node_to_partial_view(peer);
                }
            }
            MdnsEvent::Expired(list) => {
                for (peer, _) in list {
                    if !self.mdns.has_node(&peer) {
                        self.floodsub.remove_node_from_partial_view(&peer);
                    }
                }
            }
        }
    }
}