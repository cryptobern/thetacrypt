use crate::{p2p::p2p_component::P2PComponent, proxy::proxyp2p::P2PProxy, types::config::NetworkConfig};

use super::network_manager_builder::NetworkManagerBuilder;

// import here all the concrete types (like P2PComponent)
pub struct NetworkDirector;

impl NetworkDirector{
    pub async fn construct_standalone_network(builder: &mut NetworkManagerBuilder, config: NetworkConfig, my_id: u32){
        // Instanciathe the p2p compponent implementation
        let mut p2p_component = P2PComponent::new(
            config.clone(),
            my_id,
        );

        p2p_component.init().await;//to move

        builder.set_gossip_channel(Box::new(p2p_component));
    }

    pub async fn construct_proxy_network(builder: &mut NetworkManagerBuilder, config: NetworkConfig, my_id: u32){
        // Instanciathe the p2p compponent implementation
        let mut p2p_proxy = P2PProxy::new(
            config.clone(),
            my_id,
        );

        p2p_proxy.init().await;//to move

        builder.set_gossip_channel(Box::new(p2p_proxy));
    }
}
// pub fn construct_blockchain_based_network<T, G: Gossip, P: TOB<T>>(builder: &NetworkManagerBuilder<T, G, P>){

// }