#[cfg(test)]
mod tests{
    use crate::{interface::Gossip, p2p::p2p_component::P2PComponent, types::{config::{NetworkConfig, NetworkPeer}, message::{Channel, NetMessage, NetMessageMetadata}}};

    #[tokio::test]
    async fn test_multiple_peer_instantiation(){

        //Create peers
        let listening_addr="0.0.0.0";
        let localhost = "127.0.0.1";
        let peer1 = NetworkPeer{
            id: 1,
            ip: localhost.to_string(),
            port: 8081,
        };
        let peer2 = NetworkPeer{
            id: 2,
            ip: localhost.to_string(),
            port: 8082,
        };
        let peer3 = NetworkPeer{
            id: 3,
            ip: localhost.to_string(),
            port: 8083,
        };
        let peer4 = NetworkPeer{
            id: 4,
            ip: localhost.to_string(),
            port: 8084,
        };

        //Create network configuration
        let network_config1 = NetworkConfig{
            local_peer: peer1.clone(),
            peers: Some(vec![peer1.clone(),peer2.clone(), peer3.clone(), peer4.clone()]),
            proxy: None,
            base_listen_address: listening_addr.to_string(),
        };
        let network_config2 = NetworkConfig{
            local_peer: peer2.clone(),
            peers: Some(vec![peer1.clone(),peer2.clone(), peer3.clone(), peer4.clone()]),
            proxy: None,
            base_listen_address: listening_addr.to_string(),
        };
        let network_config3 = NetworkConfig{
            local_peer: peer3.clone(),
            peers: Some(vec![peer1.clone(),peer2.clone(), peer3.clone(), peer4.clone()]),
            proxy: None,
            base_listen_address: listening_addr.to_string(),
        };
        let network_config4 = NetworkConfig{
            local_peer: peer4.clone(),
            peers: Some(vec![peer1.clone(),peer2.clone(), peer3.clone(), peer4.clone()]),
            proxy: None,
            base_listen_address: listening_addr.to_string(),
        };

        //Initialize peer components
        let mut p2p_component1 = P2PComponent::new(network_config1.clone(), peer1.clone().id);
        let mut p2p_component2 = P2PComponent::new(network_config2.clone(), peer2.clone().id);
        let mut p2p_component3 = P2PComponent::new(network_config3.clone(), peer3.clone().id);
        let mut p2p_component4 = P2PComponent::new(network_config4.clone(), peer4.clone().id);


        //define the async function to initialize the peers
        let result1 = p2p_component1.init();
        let result2 = p2p_component2.init();
        let result3 = p2p_component3.init();
        let result4 = p2p_component4.init();

        let (result1, result2, result3, result4) = tokio::join!(result1, result2, result3, result4);

        //Check if the peers are connected
        assert!(result1.is_ok(), "Peer 1 failed to connect");
        assert!(result2.is_ok(), "Peer 2 failed to connect");
        assert!(result3.is_ok(), "Peer 3 failed to connect");
        assert!(result4.is_ok(), "Peer 4 failed to connect");
        
    }

    #[tokio::test]
    async fn test_broadcast_message(){

        //Create peers
        let listening_addr="0.0.0.0";
        let localhost = "127.0.0.1";

        let peer1 = NetworkPeer{
            id: 1,
            ip: localhost.to_string(),
            port: 8081,
        };
        let peer2 = NetworkPeer{
            id: 2,
            ip: localhost.to_string(),
            port: 8082,
        };
        let peer3 = NetworkPeer{
            id: 3,
            ip: localhost.to_string(),
            port: 8083,
        };
        let peer4 = NetworkPeer{
            id: 4,
            ip: localhost.to_string(),
            port: 8084,
        };

        //Create network configuration
        let network_config1 = NetworkConfig{
            local_peer: peer1.clone(),
            peers: Some(vec![peer1.clone(),peer2.clone(),peer3.clone(),peer4.clone()]),
            proxy: None,
            base_listen_address: listening_addr.to_string(),
        };
        let network_config2 = NetworkConfig{
            local_peer: peer2.clone(),
            peers: Some(vec![peer1.clone(),peer2.clone(),peer3.clone(),peer4.clone()]),
            proxy: None,
            base_listen_address: listening_addr.to_string(),
        };
        let network_config3 = NetworkConfig{
            local_peer: peer3.clone(),
            peers: Some(vec![peer1.clone(),peer2.clone(),peer3.clone(),peer4.clone()]),
            proxy: None,
            base_listen_address: listening_addr.to_string(),
        };
        let network_config4 = NetworkConfig{
            local_peer: peer4.clone(),
            peers: Some(vec![peer1.clone(),peer2.clone(),peer3.clone(),peer4.clone()]),
            proxy: None,
            base_listen_address: listening_addr.to_string(),
        };

        //Initialize peer components
        let mut p2p_component1 = P2PComponent::new(network_config1.clone(), peer1.clone().id);
        let mut p2p_component2 = P2PComponent::new(network_config2.clone(), peer2.clone().id);
        let mut p2p_component3 = P2PComponent::new(network_config3.clone(), peer3.clone().id);
        let mut p2p_component4 = P2PComponent::new(network_config4.clone(), peer4.clone().id);


        //define the async function to initialize the peers
        let result1 = p2p_component1.init();
        let result2 = p2p_component2.init();
        let result3 = p2p_component3.init();
        let result4 = p2p_component4.init();

        //Wait for the futures to complete
        let (_, _, _, _) = tokio::join!(result1, result2, result3, result4);

        //Create a test message
        let test_message = NetMessage::new("aaa".to_string(), 
        NetMessageMetadata::new(Channel::Gossip), "Hello".to_string().into_bytes());
        let test_message2 = test_message.clone();
        let test_message3 = test_message.clone();
        let test_message4 = test_message.clone();

        tokio::spawn(async move {
            let received_message2 = p2p_component2.deliver().await;
            //Check if the message was received
            match received_message2 {
                Some(msg) => assert_eq!(msg, test_message2, "Peer 2 received a different message"),
                None => assert!(false, "Peer 2 received no message"),
            }
        });

        tokio::spawn(async move {
            let received_message3 = p2p_component3.deliver().await;
            //Check if the message was received
            match received_message3 {
                Some(msg) => assert_eq!(msg, test_message3, "Peer 3 received a different message"),
                None => assert!(false, "Peer 3 received no message"),
            }
        });

        tokio::spawn(async move {
            let received_message4 = p2p_component4.deliver().await;
            //Check if the message was received
            match received_message4 {
                Some(msg) => assert_eq!(msg, test_message4, "Peer 4 received a different message"),
                None => assert!(false, "Peer 4 received no message"),
            }
        });

        //Broadcast the message
        let result = p2p_component1.broadcast(test_message.clone());
        assert!(result.is_ok(), "Broadcast failed");

    }
}