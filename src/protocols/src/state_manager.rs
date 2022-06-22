use std::collections::HashMap;

use tokio::sync::mpsc::error::TryRecvError;

use crate::rpc_network::RpcNetwork;

#[derive(Debug)]
pub enum StateUpdateCommand {
    AddNetToProtChannel {
        instance_id: String,
        sender: tokio::sync::mpsc::Sender<Vec<u8>>
    },
    AddProtToNetChannel {
        instance_id: String,
        receiver: tokio::sync::mpsc::Receiver<Vec<u8>>
    },
    GetNetToProtSender {
        instance_id: String,
        responder: tokio::sync::oneshot::Sender<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>
    },
    AddResultChannel {
        instance_id: String,
        receiver: tokio::sync::mpsc::Receiver<Option<Vec<u8>>>
    },
    GetInstanceIdExists {
        instance_id: String,
        responder: tokio::sync::oneshot::Sender<bool>
    },
    AddInstanceId {
        instance_id: String,
    }
}

pub struct StateManager{
    channels_net_to_prot: HashMap<String, tokio::sync::mpsc::Sender<Vec<u8>> >,
    channels_prot_to_net: HashMap<String, tokio::sync::mpsc::Receiver<Vec<u8>> >,
    result_channels: HashMap<String, tokio::sync::mpsc::Receiver<Option<Vec<u8>>> >,
    instances_results_map: HashMap<String, Option<Vec<u8>> >,
    state_manager_receiver: tokio::sync::mpsc::Receiver<StateUpdateCommand>,
    network_manager: RpcNetwork
}

impl StateManager{
    pub fn new(state_manager_receiver: tokio::sync::mpsc::Receiver<StateUpdateCommand>, network_manager: RpcNetwork) -> Self {
        StateManager {
            channels_net_to_prot: HashMap::new(),
            channels_prot_to_net: HashMap::new(),
            result_channels: HashMap::new(),
            instances_results_map: HashMap::new(),
            state_manager_receiver,
            network_manager,
        }
    }

    pub fn run(&mut self){
        loop {
            // Handle incoming commands (i.e., requests to modify or read the state).
            match self.state_manager_receiver.try_recv() { 
                Ok(cmd) => {
                    match cmd {
                        StateUpdateCommand::AddInstanceId { instance_id} => {
                            self.instances_results_map.insert(instance_id.clone(), None); // this updates the value if key already existed
                        }
                        StateUpdateCommand::GetInstanceIdExists { instance_id, responder} => {
                            if let Err(_) = responder.send(self.instances_results_map.contains_key(&instance_id)){
                                println!(">> SM: ERROR in GetInstanceIdExists: The receiver end of the responder dropped. Instance_id: {:?}", instance_id);    
                            }
                        },
                        StateUpdateCommand::AddNetToProtChannel { instance_id, sender } => {
                            self.channels_net_to_prot.insert(instance_id, sender); // this updates the value if key already existed
                        },
                        StateUpdateCommand::AddProtToNetChannel { instance_id, receiver } => {
                            self.channels_prot_to_net.insert(instance_id, receiver); // this updates the value if key already existed
                        },
                        StateUpdateCommand::GetNetToProtSender { instance_id, responder } => {
                            // if there is channel sender for that instance_id send it back throught the responder. Otherwise send a None.
                            let result = match self.channels_net_to_prot.get(&instance_id) {
                                Some(sender) => Some(sender.clone()),
                                None => None
                            };
                            if let Err(_) = responder.send(result){
                                println!(">> SM: ERROR in GetNetToProtSender: The receiver end of the responder dropped. Instance_id: {:?}", instance_id);    
                            }
                        },
                        StateUpdateCommand::AddResultChannel { instance_id, receiver } => {
                            self.result_channels.insert(instance_id.clone(), receiver); // this updates the value if key already existed
                        },
                    }
                },
                Err(TryRecvError::Empty) => {} //it's ok, just no new message
                Err(TryRecvError::Disconnected) => {}, // sender end closed
            };
            // Handle messages from protocol instances (send them through the network).
            for (instance_id, receiver) in self.channels_prot_to_net.iter_mut(){
                match receiver.try_recv() {
                    Ok(message) => {
                        println!(">> SM: Received decryption share in prot_to_net. Instance_id: {:?}", instance_id);
                        self.network_manager.send_to_all(instance_id.clone(), message);
                    },
                    Err(TryRecvError::Empty) => {},
                    Err(TryRecvError::Disconnected) => {}, // sender end dropped
                };
            }
            // Handle results (i.e., return values) from terminated protocol instances.
            // The result is kept in instances_results_map (step 1), all related channels are closed and removed from state (steps 2 - 4).
            // 
            let mut instances_to_remove: Vec<String> = Vec::new();
            for (instance_id, receiver) in self.result_channels.iter_mut(){
                match receiver.try_recv() {
                    Ok(message) => {
                        println!(">> SM: Received result in result_channel. Instance_id: {:?}", instance_id);
                        // 1. Store result
                        self.instances_results_map.insert(instance_id.clone(), message);
                        // 2. Remove sender from channels_net_to_prot
                        self.channels_net_to_prot.remove(instance_id);
                        println!(">> SM: Removed channel from channels_net_to_prot. Instance_id: {:?}", instance_id);
                        // 3. Close and remove receiver from channels_prot_to_net. Also check for outstanding messages in the channel and handle them.
                        match self.channels_prot_to_net.get_mut(instance_id){
                            Some(receiver) => {
                                receiver.close();
                                println!(">> SM: Closed receiver end from channels_prot_to_net. Instance_id: {:?}", instance_id);
                                // todo: code inside this while loop is duplicate. Can we avoid this
                                while let Some(message) = receiver.blocking_recv() {
                                    println!(">> SM: Received decryption share in prot_to_net. Instance_id: {:?}", instance_id);
                                    tokio::spawn( async move {
                                        self.network_manager.send_to_all(instance_id.clone(), message).await;
                                    });
                                };
                                self.channels_prot_to_net.remove(instance_id);
                                println!(">> SM: Removed channel from channels_prot_to_net. Instance_id: {:?}", instance_id);
                            },
                            None => {
                                println!(">> SM: Warning: Channel already removed from channels_prot_to_net. Instance_id: {:?}", instance_id);
                            },
                        }
                        // 4. Close and remove receiver from result_channels.
                        instances_to_remove.push(instance_id.clone());
                    },    
                    Err(TryRecvError::Empty) => {} //it's ok, just no new message
                    Err(TryRecvError::Disconnected) => {}, // sender end closed
                };
            }
            for instance_id in instances_to_remove{
                self.result_channels.remove(&instance_id);
                println!(">> SM: Removed channel from result_channels. Instance_id: {:?}", instance_id);
            }
        }
    }
}
