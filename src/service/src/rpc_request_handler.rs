use std::sync::Arc;

use chrono::Utc;
use mcore::ed25519::ecdh::public_key_validate;
use theta_orchestration::instance_manager::instance_manager::{
    InstanceManagerCommand, InstanceStatus, StartInstanceRequest,
};
use theta_orchestration::key_manager::key_manager::KeyManagerCommand;
use theta_proto::protocol_types::{
    CoinRequest, CoinResponse, KeyRequest, KeyResponse, StatusRequest, StatusResponse,
};
use theta_proto::scheme_types::{Group, PublicKeyEntry};
use theta_schemes::keys::key_store::KeyEntry;
use theta_schemes::scheme_types_impl::SchemeDetails;
use tokio::sync::oneshot;
use tonic::Code;
use tonic::{transport::Server, Request, Response, Status};

use log::{self, error, info, debug};

use theta_proto::protocol_types::{
    threshold_crypto_library_server::{ThresholdCryptoLibrary, ThresholdCryptoLibraryServer},
    DecryptRequest, DecryptResponse, SignRequest, SignResponse,
};
use theta_schemes::interface::{Ciphertext, SchemeError, Serializable, ThresholdScheme};

use theta_events::event::Event;

pub struct RpcRequestHandler {
    key_manager_command_sender: tokio::sync::mpsc::Sender<KeyManagerCommand>,
    instance_manager_command_sender: tokio::sync::mpsc::Sender<InstanceManagerCommand>,
    event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
}

#[tonic::async_trait]
impl ThresholdCryptoLibrary for RpcRequestHandler {
    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        info!("Received a decrypt request.");

        let event = Event::ReceivedDecryptionRequest {
            timestamp: Utc::now(),
        };
        self.event_emitter_sender.send(event).await.unwrap();

        // Deserialize ciphertext
        let ciphertext = match Ciphertext::from_bytes(&request.get_ref().ciphertext) {
            Ok(ctxt) => ctxt,
            Err(e) => {
                error!("Invalid ciphertext: {}", e);
                return Err(Status::aborted("Invalid ciphertext"));
            }
        };

        println!("User wants to use key {}", ciphertext.get_key_id());

        let (response_sender, response_receiver) =
            oneshot::channel::<Result<String, SchemeError>>();
        self.instance_manager_command_sender
            .send(InstanceManagerCommand::CreateInstance {
                request: StartInstanceRequest::Decryption { ciphertext },
                responder: response_sender,
            })
            .await
            .expect("Receiver for state_command_sender closed.");

        let result = response_receiver
            .await
            .expect("response_receiver.await returned Err");

        if result.is_err() {
            error!(
                "Error creating instance: {}",
                result.as_ref().unwrap_err().to_string()
            );
            return Err(Status::aborted(result.unwrap_err().to_string()));
        }

        Ok(Response::new(DecryptResponse {
            instance_id: result.unwrap(),
        }))
    }

    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        info!("Received a signature request");
        let event = Event::ReceivedSigningRequest {
            timestamp: Utc::now(),
        };
        self.event_emitter_sender.send(event).await.unwrap();

        let req: &SignRequest = request.get_ref();

        let scheme = ThresholdScheme::from_i32(req.scheme);
        if scheme.is_none() {
            return Err(Status::aborted("Invalid scheme"));
        }
        let scheme = scheme.unwrap();

        let group = Group::from_i32(req.group);
        if group.is_none() {
            return Err(Status::aborted("Invalid group"));
        }
        let group = group.unwrap();

        let (response_sender, response_receiver) =
            oneshot::channel::<Result<String, SchemeError>>();
        self.instance_manager_command_sender
            .send(InstanceManagerCommand::CreateInstance {
                request: StartInstanceRequest::Signature {
                    message: req.message.clone(),
                    label: req.label.clone(),
                    group,
                    scheme,
                    key_id: req.key_id.clone(),
                },
                responder: response_sender,
            })
            .await
            .expect("Receiver for state_command_sender closed.");

        let result = response_receiver
            .await
            .expect("response_receiver.await returned Err");

        if result.is_err() {
            error!(
                "Error creating instance: {}",
                result.as_ref().unwrap_err().to_string()
            );
            return Err(Status::aborted(result.unwrap_err().to_string()));
        }

        Ok(Response::new(SignResponse {
            instance_id: result.unwrap(),
        }))
    }

    async fn flip_coin(
        &self,
        request: Request<CoinRequest>,
    ) -> Result<Response<CoinResponse>, Status> {
        info!("Received a coin flip request.");

        let event = Event::ReceivedCoinRequest {
            timestamp: Utc::now(),
        };
        self.event_emitter_sender.send(event).await.unwrap();

        let req: &CoinRequest = request.get_ref();

        let scheme = ThresholdScheme::from_i32(req.scheme);
        if scheme.is_none() {
            return Err(Status::aborted("Invalid scheme"));
        }
        let scheme = scheme.unwrap();

        let group = Group::from_i32(req.group);
        if group.is_none() {
            return Err(Status::aborted("Invalid group"));
        }
        let group = group.unwrap();

        let (response_sender, response_receiver) =
            oneshot::channel::<Result<String, SchemeError>>();
        self.instance_manager_command_sender
            .send(InstanceManagerCommand::CreateInstance {
                request: StartInstanceRequest::Coin {
                    name: req.name.clone(),
                    scheme,
                    group,
                    key_id: req.key_id.clone(),
                },
                responder: response_sender,
            })
            .await
            .expect("Receiver for state_command_sender closed.");

        let result = response_receiver
            .await
            .expect("response_receiver.await returned Err");

        if result.is_err() {
            error!(
                "Error creating instance: {}",
                result.as_ref().unwrap_err().to_string()
            );
            return Err(Status::aborted(result.unwrap_err().to_string()));
        }

        Ok(Response::new(CoinResponse {
            instance_id: result.unwrap(),
        }))
    }

    async fn get_public_keys(
        &self,
        _request: Request<KeyRequest>,
    ) -> Result<Response<KeyResponse>, Status> {
        info!("Received a get_public_keys request.");

        let (response_sender, response_receiver) = oneshot::channel::<Vec<Arc<PublicKeyEntry>>>();

        let cmd = KeyManagerCommand::ListAvailableKeys {
            responder: response_sender,
        };

        self.key_manager_command_sender
            .send(cmd)
            .await
            .expect("Receiver for key_manager_command_sender closed.");
        let key_entries = response_receiver
            .await
            .expect("response_receiver.await returned Err");

        let mut public_keys = Vec::new();
        for key in &key_entries {
            public_keys.push((**key).clone());
        }

        return Ok(Response::new(KeyResponse { keys: public_keys }));
    }

    async fn get_status(
        &self,
        request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        debug!("Received a result request.");
        let req: &StatusRequest = request.get_ref();

        // Get status of the instance by contacting the state manager
        let (response_sender, response_receiver) = oneshot::channel::<Option<InstanceStatus>>();
        let cmd = InstanceManagerCommand::GetInstanceStatus {
            instance_id: req.instance_id.clone(),
            responder: response_sender,
        };
        self.instance_manager_command_sender
            .send(cmd)
            .await
            .expect("Receiver for state_command_sender closed.");
        let status = response_receiver
            .await
            .expect("response_receiver.await returned Err");

        if status.is_none() {
            return Err(Status::not_found("Instance not found"));
        }

        let status = status.unwrap();

        let result = match status.result {
            Some(r) => Some(r.unwrap()),
            None => None,
        };

        let response = StatusResponse {
            instance_id: req.instance_id.clone(),
            scheme: status.scheme.into(),
            group: status.group.into(),
            is_finished: status.finished,
            result,
            key_id: None,
        };
        Ok(Response::new(response))
    }
}

pub async fn init(
    rpc_listen_address: String,
    rpc_listen_port: u16,
    instance_manager_command_sender: tokio::sync::mpsc::Sender<InstanceManagerCommand>,
    key_manager_command_sender: tokio::sync::mpsc::Sender<KeyManagerCommand>,
    event_emitter_sender: tokio::sync::mpsc::Sender<Event>,
) {
    // Start server
    let rpc_addr = format!("{}:{}", rpc_listen_address, rpc_listen_port);
    let service = RpcRequestHandler {
        key_manager_command_sender: key_manager_command_sender,
        instance_manager_command_sender: instance_manager_command_sender,
        event_emitter_sender,
    };
    Server::builder()
        .add_service(ThresholdCryptoLibraryServer::new(service))
        // .serve(format!("[{rpc_listen_address}]:{rpc_listen_port}").parse().unwrap())
        .serve(rpc_addr.parse().unwrap())
        .await
        .expect("");
    info!("Request handler is starting. Listening for RPC on address: {rpc_addr}");
}
