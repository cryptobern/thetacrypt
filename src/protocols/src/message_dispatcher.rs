use std::collections::HashMap;
use tokio::sync::mpsc::{Receiver, Sender};

use network::types::message::NetMessage;

use crate::types::InstanceId;

const BACKLOG_CHECK_INTERVAL: u32 = 600; //seconds.

#[derive(Debug)]
pub(crate) enum MessageDispatcherCommand {
    // Inform the MessageDispatcher that a new protocol instance has been created.
    // Upon receiving this command, the MessageDispatcher creates a new channel to communicate with the new instance
    // and returns (by sending it through the responder) the receiver end of that channel.
    InsertInstance {
        instance_id: String,
        responder: tokio::sync::oneshot::Sender<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    },
    // Inform the MessageDispatcher that a protocol instance has terminated.
    RemoveInstance {
        instance_id: String,
    },
}

// BacklogData keeps all the messages that are destined for a specific instance,
// plus a field checked, which is used to detect too old backlog data.
struct BacklogData {
    messages: Vec<Vec<u8>>,
    checked: bool,
}

// MessageDispatcher is responsible for forwarding messages to the appropriate instance
// and backlogging messages when instance has not yet started.
// For every new protocol instance, it creates a channel and stores the sender end in instance_senders.
pub(crate) struct MessageDispatcher {
    instance_senders: HashMap<InstanceId, tokio::sync::mpsc::Sender<Vec<u8>>>,
    backlogged_instances: HashMap<InstanceId, BacklogData>,
    backlog_interval: tokio::time::Interval,
    dispatcher_command_receiver: Receiver<MessageDispatcherCommand>,
    message_receiver: Receiver<NetMessage>,
}

impl MessageDispatcher {
    pub(crate) fn new(
        command_receiver: Receiver<MessageDispatcherCommand>,
        message_receiver: Receiver<NetMessage>,
    ) -> Self {
        MessageDispatcher {
            instance_senders: HashMap::new(),
            backlogged_instances: HashMap::new(),
            backlog_interval: tokio::time::interval(tokio::time::Duration::from_secs(
                BACKLOG_CHECK_INTERVAL as u64,
            )),
            dispatcher_command_receiver: command_receiver,
            message_receiver,
        }
    }

    pub(crate) async fn run(&mut self) {
        loop {
            tokio::select! {

                dispatcher_command = self.dispatcher_command_receiver.recv() => {
                    let command = dispatcher_command.expect("Sender for dispatcher_command_receiver closed.");
                    match command {
                        MessageDispatcherCommand::InsertInstance { instance_id , responder} => {
                            if ! self.instance_senders.contains_key(&instance_id) {
                                // Create channel for new instance and send the receiver end back to the caller
                                let (dispatcher_to_instance_sender, dispatcher_to_instance_receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                                responder.send(dispatcher_to_instance_receiver).expect("The receiver end of the responder in MessageDispatcherCommand::GetReceiverForNewInstance has been closed.");
                                // Check if we have any backlogged messages for the new instance. If yes, remove them from backlogged_data and forward all messages..
                                if let Some(backlog_data) =  self.backlogged_instances.remove(&instance_id) {
                                    for message_data in backlog_data.messages {
                                        MessageDispatcher::forward(&dispatcher_to_instance_sender, message_data, &instance_id).await;
                                    }
                                }
                                // Keep sender end of channel in instance_senders.
                                self.instance_senders.insert(instance_id, dispatcher_to_instance_sender);
                            }
                        },
                        MessageDispatcherCommand::RemoveInstance { instance_id} => {
                            self.instance_senders.remove(&instance_id);
                        }
                    }
                }

                incoming_message = self.message_receiver.recv() => {
                    let NetMessage{instance_id, is_total_order, message_data} = incoming_message.expect("The channel for incoming_message_receiver has been closed.");
                    // Check whether a channel exists for the given instance_id.
                    if let Some(instance_sender) = self.instance_senders.get(&instance_id) {
                        // If yes, forward the message to the instance. (ok if the following returns Err, it only means the instance has in the meanwhile finished.)
                        MessageDispatcher::forward(&instance_sender, message_data, &instance_id).await;
                    } else {
                        // Otherwise, backlog the message. This can happen for two reasons:
                        // - The instance has already finished and the corresponding sender has been removed from the instance_senders.
                        // - The instance has not yet started because the corresponding request has not yet arrived.
                        // In both cases, we backlog the message. If the instance has already been finished,
                        // the backlog will be deleted after at most 2*BACKLOG_CHECK_INTERVAL seconds
                        println!(
                            ">> FORW: Backlogging message for instance with id: {:?}",
                            &instance_id
                        );
                        if let Some(backlog_data) =  self.backlogged_instances.get_mut(&instance_id) {
                            backlog_data.messages.push(message_data);
                        } else {
                            let mut backlog_data = BacklogData{ messages: Vec::new(), checked: false };
                            backlog_data.messages.push(message_data);
                            self.backlogged_instances.insert(instance_id, backlog_data);
                        }
                    }
                }

                // Detect and delete too old backlog data, so the backlogged_instances field does not grow forever.
                // We assume that an instance will be started at most BACKLOG_CHECK_INTERVAL seconds
                // after a message for that instance has been received. Otherwise, it will never start, so we can delete backlogged messages.
                // Every BACKLOG_CHECK_INTERVAL seconds, go through all backlogged_instances.
                // If the field 'checked' is true, delete the backlogged instance. If it is false, set it to true.
                // This ensures that, if a backlogged instance gets deleted, then it has been waiting for at least BACKLOG_CHECK_INTERVAL seconds.
                _ = self.backlog_interval.tick() => {
                    self.backlogged_instances.retain(|_, v| v.checked == false);
                    for (_, v) in self.backlogged_instances.iter_mut(){
                        v.checked = true;
                    }
                    println!(">> FORW: Old backlogged instances deleted");
                }

            }
        }
    }

    async fn forward(
        instance_sender: &Sender<Vec<u8>>,
        message_data: Vec<u8>,
        instance_id: &String,
    ) {
        instance_sender
            .send(message_data)
            .await
            .map_err(|_err| {
                println!(
                    ">> FORW: Instance {:?} has finished, message not forwarded.",
                    instance_id
                )
            })
            .ok();
        println!(
            ">> FORW: Forwarded message to instance with id: {:?}",
            instance_id
        );
    }
}
