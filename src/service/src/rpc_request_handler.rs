use std::borrow::BorrowMut;
use std::sync::Arc;
use theta_network::config::static_net;
use rand::Rng;
use rand::distributions::Alphanumeric;
use theta_orchestration::instance_manager::instance_manager::{InstanceManager, StartInstanceRequest, InstanceManagerCommand, InstanceStatus};
use theta_orchestration::state_manager::{StateManagerMsg, StateManagerResponse};
use theta_protocols::interface::ProtocolError;
use theta_schemes::scheme_types_impl::{SchemeDetails, GroupDetails};
use theta_proto::protocol_types::threshold_crypto_library_client::ThresholdCryptoLibraryClient;
use theta_proto::protocol_types::{CoinRequest, CoinResponse, KeyRequest, KeyResponse, StatusRequest, StatusResponse, PublicKeyEntry};
use theta_proto::scheme_types::Group;
use tokio::sync::{mpsc::Sender, oneshot};
use tonic::Code;
use tonic::{transport::Server, Request, Response, Status};
use std::str;

use log::{self, info, error};
use log4rs;

use mcore::hash256::HASH256;
use theta_network::types::message::NetMessage;
use theta_schemes::interface::{Ciphertext, Serializable, Signature, ThresholdScheme, ThresholdCoin, InteractiveThresholdSignature, ThresholdCryptoError};
use theta_proto::protocol_types::{
    threshold_crypto_library_server::{ThresholdCryptoLibrary, ThresholdCryptoLibraryServer},
    DecryptResponse, DecryptRequest, SignRequest, SignResponse,
};

use theta_protocols::threshold_cipher::protocol::ThresholdCipherProtocol;
use theta_protocols::threshold_signature::protocol::{ThresholdSignatureProtocol, ThresholdSignaturePrecomputation};
use theta_protocols::threshold_coin::protocol::ThresholdCoinProtocol;
use theta_orchestration::{
    keychain::KeyChain,
    state_manager::{StateManager, StateManagerCommand},
    types::{Key},
};

const NUM_PRECOMPUTATIONS:i32 = 3;

pub struct RpcRequestHandler {
    state_command_sender: tokio::sync::mpsc::Sender<StateManagerMsg>,
    instance_manager_command_sender: tokio::sync::mpsc::Sender<InstanceManagerCommand>,
    outgoing_message_sender: tokio::sync::mpsc::Sender<NetMessage>
}

impl RpcRequestHandler {
    /*
    pub async fn do_sign(&self, 
        request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        println!(">> REQH: Received a signing request.");
        let req: &SignRequest = request.get_ref();
        let mut instance_id;
        let mut prot;
        let mut instance = Option::None;

        // If scheme is Frost, we can make use of precomputation
        if req.scheme == ThresholdScheme::Frost.get_id() as i32 {
            println!(">> REQH: Scheme is FROST, fetching precomputations");
            instance = self.pop_frost_precomputation().await;

            if instance.is_none() {
                println!(">> REQH: No more precomputations left, create new precomputations");
                // no more precomputations left, start another round of precomputation
                for i in 0..NUM_PRECOMPUTATIONS {
                    let mut s = String::from_utf8(req.label.clone()).unwrap();
                    s.push_str(&(i as u32).to_string());
                    (instance_id, prot) = match self
                    .get_precompute_instance(&s.into_bytes(), &req.key_id, req.scheme as u8, req.group as u8)
                    .await
                    {
                        Ok((instance_id, prot)) => (instance_id, prot),
                        Err(err) => return Err(err),
                    };
            
                    // Start it in a new thread, so that the client does not block until the protocol is finished.
                    let state_command_sender2 = self.state_command_sender.clone();
                    tokio::spawn(async move {
                        let result = prot.run().await;
            
                        // Protocol terminated, update state with the result.
                        println!(
                            ">> REQH: Precomputed FROST round"
                        );
                        
                        RpcRequestHandler::push_frost_precomputation(
                            state_command_sender2,
                            result.unwrap()
                        )
                        .await.expect("Error adding frost precomputation");
                    });
                }
            }

            instance = self.pop_frost_precomputation().await;
        } 
         
        // Make all required checks and create the new protocol instance
        let (instance_id, mut prot) = match self
            .get_signature_instance(Option::Some(&req.message), &req.label, &req.key_id, req.scheme as u8, req.group as u8, instance)
            .await {
            Ok((instance_id, prot)) => (instance_id, prot),
            Err(err) => return Err(err),
        };
        
        // Start it in a new thread, so that the client does not block until the protocol is finished.
        let state_command_sender2 = self.state_command_sender.clone();
        let dispatcher_command_sender2 = self.instance_manager_command_sender.clone();
        let instance_id2 = instance_id.clone();
        tokio::spawn(async move {
            let result = prot.run().await;

            // Protocol terminated, update state with the result.
            println!(
                ">> REQH: Received result from protocol with instance_id: {:?}",
                instance_id2
            );
            RpcRequestHandler::update_signature_instance_result(
                instance_id2.clone(),
                result,
                state_command_sender2,
                dispatcher_command_sender2,
            )
            .await;
        });

        return Ok(Response::new(SignResponse {
            instance_id: instance_id.clone(),
        }));
    }
*/}

#[tonic::async_trait]
impl ThresholdCryptoLibrary for RpcRequestHandler {
    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        info!(">> REQH: Received a decrypt request.");
        let req: &DecryptRequest = request.get_ref();

        // Deserialize ciphertext
        let ciphertext = match Ciphertext::deserialize(&request.get_ref().ciphertext) {
            Ok(ctxt) => ctxt,
            Err(err) => {
                error!("Invalid ciphertext");
                return Err(Status::aborted("Invalid ciphertext"));
            }
        };

        let (response_sender, response_receiver) = oneshot::channel::<Result<String, ThresholdCryptoError>>();
        self.instance_manager_command_sender
            .send(InstanceManagerCommand::CreateInstance { 
                request: StartInstanceRequest::Decryption { 
                    ciphertext 
                }, 
                responder: response_sender 
            })
            .await
            .expect("Receiver for state_command_sender closed.");

        let result = 
            response_receiver.await.expect("response_receiver.await returned Err");

        if result.is_err() {
            error!("Eror creating instance: {}", result.as_ref().unwrap_err().to_string());
            return Err(Status::aborted(result.unwrap_err().to_string()));
        }

        Ok(Response::new(DecryptResponse{
            instance_id: result.unwrap()
        }))
    }

    async fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
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

        let (response_sender, response_receiver) = oneshot::channel::<Result<String, ThresholdCryptoError>>();
        self.instance_manager_command_sender
            .send(InstanceManagerCommand::CreateInstance { 
                request: StartInstanceRequest::Signature {
                    message: req.message.clone(),
                    label: req.label.clone(),
                    group,
                    scheme
                }, 
                responder: response_sender 
            })
            .await
            .expect("Receiver for state_command_sender closed.");

        let result = 
            response_receiver.await.expect("response_receiver.await returned Err");

        if result.is_err() {
            error!("Error creating instance: {}", result.as_ref().unwrap_err().to_string());
            return Err(Status::aborted(result.unwrap_err().to_string()));
        }

        Ok(Response::new(SignResponse{
            instance_id: result.unwrap()
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

        let (response_sender, response_receiver) = oneshot::channel::<Result<String, ThresholdCryptoError>>();
        self.instance_manager_command_sender
            .send(InstanceManagerCommand::CreateInstance { 
                request: StartInstanceRequest::Coin { 
                    name: req.name.clone(), 
                    scheme, 
                    group 
                }, 
                responder: response_sender 
            })
            .await
            .expect("Receiver for state_command_sender closed.");

        let result = 
            response_receiver.await.expect("response_receiver.await returned Err");

        if result.is_err() {
            error!("Error creating instance: {}", result.as_ref().unwrap_err().to_string());
            return Err(Status::aborted(result.unwrap_err().to_string()));
        }


        Ok(Response::new(CoinResponse{
            instance_id: result.unwrap()
        }))
    }

    async fn get_public_keys(
        &self,
        request: Request<KeyRequest>,
    ) -> Result<Response<KeyResponse>, Status> {
        info!("Received a get_public_keys_for_encryption request.");
        let (response_sender, response_receiver) = oneshot::channel::<StateManagerResponse>();
        
        let cmd = StateManagerMsg {
            command:StateManagerCommand::GetEncryptionKeys {},
            responder:Some(response_sender)
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
            return Ok(Response::new(KeyResponse {
                keys: public_keys,
            }));
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
            responder: response_sender
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
            None => None
        };

        let response = StatusResponse {
            instance_id: req.instance_id.clone(),
            scheme: status.scheme.into(),
            group: status.group.into(),
            is_finished: status.finished,
            result,
            key_id: None
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
    let (instance_manager_sender, 
        instance_manager_receiver) =
        tokio::sync::mpsc::channel::<InstanceManagerCommand>(32);

    // Spawn InstanceManager
    // Takes ownershiip of instance_manager_receiver, incoming_message_receiver, state_command_sender
    info!("Initiating InstanceManager.");

    let state_cmd_sender = state_command_sender.clone();
    let inst_cmd_sender = instance_manager_sender.clone();
    let outgoing_p2p_sender = outgoing_message_sender.clone();

    tokio::spawn(async move {
        let mut mfw = InstanceManager::new(state_cmd_sender, 
            instance_manager_receiver,
            inst_cmd_sender,
            outgoing_p2p_sender,
            incoming_message_receiver);
        mfw.run().await;
    });

    // Start server
    let rpc_addr = format!("{}:{}", rpc_listen_address, rpc_listen_port);
    let service = RpcRequestHandler {
        state_command_sender: state_command_sender,
        instance_manager_command_sender: instance_manager_sender,
        outgoing_message_sender: outgoing_message_sender
    };
    Server::builder()
        .add_service(ThresholdCryptoLibraryServer::new(service))
        // .serve(format!("[{rpc_listen_address}]:{rpc_listen_port}").parse().unwrap())
        .serve(rpc_addr.parse().unwrap())
        .await
        .expect("");
    info!("Request handler is starting. Listening for RPC on address: {rpc_addr}");
}
