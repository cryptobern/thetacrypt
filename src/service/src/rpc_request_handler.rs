use theta_orchestration::instance_manager::instance_manager::{
    InstanceManager, InstanceManagerCommand, InstanceStatus, StartInstanceRequest,
};
use theta_orchestration::state_manager::{StateManagerMsg, StateManagerResponse};
use theta_proto::protocol_types::{
    CoinRequest, CoinResponse, KeyRequest, KeyResponse, PublicKeyEntry, StatusRequest,
    StatusResponse,
};
use theta_proto::scheme_types::Group;
use tokio::sync::oneshot;
use tonic::Code;
use tonic::{transport::Server, Request, Response, Status};

use log::{self, error, info};

use theta_network::types::message::NetMessage;
use theta_proto::protocol_types::{
    threshold_crypto_library_server::{ThresholdCryptoLibrary, ThresholdCryptoLibraryServer},
    DecryptRequest, DecryptResponse, SignRequest, SignResponse,
};
use theta_schemes::interface::{Ciphertext, Serializable, ThresholdCryptoError, ThresholdScheme};

use theta_orchestration::{
    keychain::KeyChain,
    state_manager::{StateManager, StateManagerCommand},
};

pub struct RpcRequestHandler {
    state_command_sender: tokio::sync::mpsc::Sender<StateManagerMsg>,
    instance_manager_command_sender: tokio::sync::mpsc::Sender<InstanceManagerCommand>,
    outgoing_message_sender: tokio::sync::mpsc::Sender<NetMessage>,
}

#[tonic::async_trait]
impl ThresholdCryptoLibrary for RpcRequestHandler {
    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        info!(">> REQH: Received a decrypt request.");

        // Deserialize ciphertext
        let ciphertext = match Ciphertext::deserialize(&request.get_ref().ciphertext) {
            Ok(ctxt) => ctxt,
            Err(_) => {
                error!("Invalid ciphertext");
                return Err(Status::aborted("Invalid ciphertext"));
            }
        };

        let (response_sender, response_receiver) =
            oneshot::channel::<Result<String, ThresholdCryptoError>>();
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
                "Eror creating instance: {}",
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
            oneshot::channel::<Result<String, ThresholdCryptoError>>();
        self.instance_manager_command_sender
            .send(InstanceManagerCommand::CreateInstance {
                request: StartInstanceRequest::Signature {
                    message: req.message.clone(),
                    label: req.label.clone(),
                    group,
                    scheme,
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
            oneshot::channel::<Result<String, ThresholdCryptoError>>();
        self.instance_manager_command_sender
            .send(InstanceManagerCommand::CreateInstance {
                request: StartInstanceRequest::Coin {
                    name: req.name.clone(),
                    scheme,
                    group,
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
        info!("Received a get_public_keys_for_encryption request.");
        let (response_sender, response_receiver) = oneshot::channel::<StateManagerResponse>();

        let cmd = StateManagerMsg {
            command: StateManagerCommand::GetEncryptionKeys {},
            responder: Some(response_sender),
        };

        self.state_command_sender
            .send(cmd)
            .await
            .expect("Receiver for state_command_sender closed.");
        let res = response_receiver
            .await
            .expect("response_receiver.await returned Err");

        if let StateManagerResponse::KeyVec(key_entries) = res {
            let mut public_keys: Vec<PublicKeyEntry> = Vec::new();
            for entry in key_entries {
                let e = PublicKeyEntry {
                    id: entry.id.clone(),
                    scheme: entry.sk.get_scheme() as i32,
                    group: entry.sk.get_group() as i32,
                    key: match entry.sk.get_public_key().serialize() {
                        Ok(key_ser) => key_ser,
                        Err(err) => return Err(Status::new(Code::Internal, err.to_string())),
                    },
                };
                public_keys.push(e);
            }
            return Ok(Response::new(KeyResponse { keys: public_keys }));
        }

        error!("Error getting keys");
        Err(Status::aborted("Error getting keys"))
    }

    async fn get_status(
        &self,
        request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        info!("Received a result request.");
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
    keychain: KeyChain,
    incoming_message_receiver: tokio::sync::mpsc::Receiver<NetMessage>,
    outgoing_message_sender: tokio::sync::mpsc::Sender<NetMessage>,
) {
    // Channel to send commands to the StateManager.
    // Used by the RpcRequestHandler, when a new request is received (it takes ownership state_command_sender)
    // The channel must never be closed.
    let (state_command_sender, state_command_receiver) =
        tokio::sync::mpsc::channel::<StateManagerMsg>(32);

    // Spawn StateManager.
    // Takes ownerhsip of keychain and state_command_receiver
    info!("Initiating the state manager.");
    tokio::spawn(async move {
        let mut sm = StateManager::new(keychain, state_command_receiver);
        sm.run().await;
    });

    // Channel to send commands to the InstanceManager.
    // The sender end is owned by the RpcRequestHandler and must never be closed.
    let (instance_manager_sender, instance_manager_receiver) =
        tokio::sync::mpsc::channel::<InstanceManagerCommand>(32);

    // Spawn InstanceManager
    // Takes ownershiip of instance_manager_receiver, incoming_message_receiver, state_command_sender
    info!("Initiating InstanceManager.");

    let state_cmd_sender = state_command_sender.clone();
    let inst_cmd_sender = instance_manager_sender.clone();
    let outgoing_p2p_sender = outgoing_message_sender.clone();

    tokio::spawn(async move {
        let mut mfw = InstanceManager::new(
            state_cmd_sender,
            instance_manager_receiver,
            inst_cmd_sender,
            outgoing_p2p_sender,
            incoming_message_receiver,
        );
        mfw.run().await;
    });

    // Start server
    let rpc_addr = format!("{}:{}", rpc_listen_address, rpc_listen_port);
    let service = RpcRequestHandler {
        state_command_sender,
        instance_manager_command_sender: instance_manager_sender,
        outgoing_message_sender,
    };
    Server::builder()
        .add_service(ThresholdCryptoLibraryServer::new(service))
        // .serve(format!("[{rpc_listen_address}]:{rpc_listen_port}").parse().unwrap())
        .serve(rpc_addr.parse().unwrap())
        .await
        .expect("");
    info!("Request handler is starting. Listening for RPC on address: {rpc_addr}");
}
