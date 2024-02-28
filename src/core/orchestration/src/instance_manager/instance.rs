use core::fmt;
use theta_proto::scheme_types::{Group, ThresholdScheme};
use theta_protocols::interface::ProtocolError;
use tokio::sync::mpsc::error::SendError;
use theta_network::types::message::NetMessage;

pub struct Instance {
    id: String,
    scheme: ThresholdScheme,
    group: Group,
    message_channel_sender: tokio::sync::mpsc::Sender<NetMessage>,
    status: String,
    finished: bool,
    result: Option<Result<Vec<u8>, ProtocolError>>,
}

impl fmt::Display for Instance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Instance {{\nid:{}\n, scheme:{}\ngroup:{}\nstatus:{}\n }}",
            self.id,
            self.scheme.as_str_name(),
            self.group.as_str_name(),
            &self.status
        )
    }
}

impl Instance {
    pub fn new(
        id: String,
        scheme: ThresholdScheme,
        group: Group,
        message_channel_sender: tokio::sync::mpsc::Sender<NetMessage>,
    ) -> Self {
        return Self {
            id,
            scheme,
            group,
            message_channel_sender,
            status: String::from("created"),
            finished: false,
            result: Option::None,
        };
    }

    pub fn set_status(&mut self, status: &str) {
        self.status = String::from(status);
    }

    pub fn is_finished(&self) -> bool {
        return self.finished;
    }

    pub fn get_result(&self) -> &Option<Result<Vec<u8>, ProtocolError>> {
        return &self.result;
    }

    pub fn set_result(&mut self, result: Result<Vec<u8>, ProtocolError>) {
        self.result = Some(result);
        self.finished = true;
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        self.scheme.clone()
    }

    pub fn get_group(&self) -> Group {
        self.group.clone()
    }

    pub async fn send_message(&self, message: NetMessage) -> Result<(), SendError<NetMessage>> {
        self.message_channel_sender.send(message).await
    }

    pub fn get_sender(&self) -> tokio::sync::mpsc::Sender<NetMessage>{
        self.message_channel_sender.clone()
    }
}
