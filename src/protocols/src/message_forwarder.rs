use std::collections::{HashMap, VecDeque};

use network::types::message::P2pMessage;
use tokio::sync::{oneshot, mpsc::{Receiver, Sender}};

use crate::types::{InstanceId, StateUpdateCommand, InstanceStatus, MessageForwarderCommand};


const BACKLOG_MAX_RETRIES: u32 = 10;
const BACKLOG_WAIT_INTERVAL: u32 = 5; //seconds. todo: exponential backoff
const CHECK_TERMINATED_CHANNELS_INTERVAL: u32 = 30;


// MessageForwarder is responsible for forwarding messages to the appropriate instance (by maintaining a channel with each instance)
// and backlogging messages when instance has not yet started.
pub(crate) struct MessageForwarder {
    instance_senders: HashMap<InstanceId, tokio::sync::mpsc::Sender<Vec<u8>> >,
    backlogged_messages: VecDeque<(P2pMessage, u32)>,
    backlog_interval: tokio::time::Interval,
    forwarder_command_receiver: Receiver<MessageForwarderCommand>,
    message_receiver: Receiver<P2pMessage>,
    state_command_sender: Sender<StateUpdateCommand>
}

impl MessageForwarder {
    pub(crate) fn new(command_receiver: Receiver<MessageForwarderCommand>, message_receiver: Receiver<P2pMessage>, state_command_sender: Sender<StateUpdateCommand>) -> Self {
        MessageForwarder{
            instance_senders: HashMap::new(),
            backlogged_messages: VecDeque::new(),
            backlog_interval: tokio::time::interval(tokio::time::Duration::from_secs(BACKLOG_WAIT_INTERVAL as u64)),
            forwarder_command_receiver: command_receiver,
            message_receiver,
            state_command_sender,
        }
    }

    pub(crate) async fn run(&mut self) {
        // let check_terminated_interval = tokio::time::interval(tokio::time::Duration::from_secs(CHECK_TERMINATED_CHANNELS_INTERVAL as u64));
        loop {
            tokio::select! {
                forwarder_command = self.forwarder_command_receiver.recv() => { // Received a command.
                    let command = forwarder_command.expect("Sender for forwarder_command_receiver closed.");
                    match command {
                        MessageForwarderCommand::GetReceiverForNewInstance { instance_id , responder} => {
                            let (message_to_instance_sender, message_to_instance_receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                            self.instance_senders.insert(instance_id, message_to_instance_sender);
                            responder.send(message_to_instance_receiver).expect("The receiver for responder in MessageForwarderCommand::GetReceiverForNewInstance has been closed.");
                        },
                        MessageForwarderCommand::RemoveReceiverForInstance { instance_id} => {
                            self.instance_senders.remove(&instance_id);
                        }
                    }
                }
                
                incoming_message = self.message_receiver.recv() => { // An incoming message was received.
                    let P2pMessage{instance_id, message_data} = incoming_message.expect("The channel for incoming_message_receiver has been closed.");
                    self.forward_or_backlog(&instance_id, message_data, BACKLOG_MAX_RETRIES).await;
                }

                _ = self.backlog_interval.tick() => { // Retry sending the backlogged messages
                    for _ in 0..self.backlogged_messages.len() { // always pop_front() and push_back(). If we pop_front() exactly backlogged_messages.len() times, we are ok.
                        let (P2pMessage{instance_id, message_data}, retries_left) = self.backlogged_messages.pop_front().unwrap(); 
                        self.forward_or_backlog(&instance_id, message_data, retries_left).await;
                    }
                    
                }
                
            }
        }
    }


    async fn forward_or_backlog(&mut self,
                                instance_id: &String, 
                                message_data: Vec<u8>, 
                                backlog_retries_left: u32,){
        // A channel was found for the given instance_id.
        if let Some(instance_sender) = self.instance_senders.get(instance_id) {
            // It is ok if the following returns Err, it only means the instance has in the meanwhile finished.
            instance_sender.send(message_data).await.map_err(|_err| println!(">> FORW: Instance {:?} has finished,", &instance_id)).ok(); 
            println!(">> FORW: Forwarded message in net_to_prot. Instance_id: {:?}", &instance_id);
        }
        else { 
            // No channel was found for the given instance_id. This can happen for two reasons:
            // - The instance has already finished and the corresponding sender has been removed from the instance_senders.
            // - The instance has not yet started because the corresponding request has not yet arrived.
            // Ask the StateManager to find out what is the case.
            let (response_sender, response_receiver) = oneshot::channel::<InstanceStatus>();
            let cmd = StateUpdateCommand::GetInstanceStatus { 
                instance_id: instance_id.clone(),
                responder: response_sender
            };
            self.state_command_sender.send(cmd).await.expect("The receiver for state_command_sender3 has been closed.");
            let status = response_receiver.await.expect("The sender for response_receiver dropped before sending a response.");
            if ! status.started { 
            // The instance has not yet started. Backlog the message, except if it was already backlogged too many times.
                if backlog_retries_left > 0 {
                    self.backlogged_messages.push_back((P2pMessage{instance_id: instance_id.clone(), message_data}, backlog_retries_left - 1));
                    println!(">> FORW: Could not forward message to instance. Instance_id: {instance_id} does not exist yet. Retrying after {BACKLOG_WAIT_INTERVAL} seconds. Retries left: {backlog_retries_left}.");
                }
                else {
                    println!(">> FORW: Could not forward message to protocol instance. Abandoned after {BACKLOG_MAX_RETRIES} retries. Instance_id: {instance_id}");
                }
            }
            else if status.finished { 
            // The instance has already finished. Do not backlog the message.
                // println!(">> FORW: Did not forward message in net_to_prot. Instance already terminated. Instance_id: {:?}", &instance_id);
            }
            else { 
            // This should never happen. If status.started and !status.terminated, there should be a channel to that instance.
                println!(">> FORW: INTERNAL ERROR: Could not find channel to instance. Instance_id: {:?}", &instance_id);
            }
        }
    }
}