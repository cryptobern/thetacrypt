use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc::Sender, oneshot};
use tonic::Code;
use tonic::{transport::Server, Request, Response, Status};

use mcore::hash256::HASH256;
use network::types::message::P2pMessage;
use schemes::interface::{Ciphertext, Serializable};
use thetacrypt_proto::protocol_types::threshold_crypto_library_server::{
    ThresholdCryptoLibrary, ThresholdCryptoLibraryServer,
};
use thetacrypt_proto::protocol_types::{DecryptReponse, DecryptRequest};
use thetacrypt_proto::protocol_types::{DecryptSyncReponse, DecryptSyncRequest};
use thetacrypt_proto::protocol_types::{GetDecryptResultRequest, GetDecryptResultResponse};
use thetacrypt_proto::protocol_types::{
    GetPublicKeysForEncryptionRequest, GetPublicKeysForEncryptionResponse, PublicKeyEntry,
};
use thetacrypt_proto::protocol_types::{PushDecryptionShareRequest, PushDecryptionShareResponse};

use crate::threshold_cipher_protocol::ThresholdCipherProtocol;
use crate::types::StateUpdateCommand;
use crate::{
    keychain::KeyChain,
    message_forwarder::MessageForwarder,
    state_manager::StateManager,
    types::{InstanceStatus, Key, MessageForwarderCommand, ProtocolError},
};

fn assign_decryption_instance_id(ctxt: &Ciphertext) -> String {
    let mut ctxt_digest = HASH256::new();
    ctxt_digest.process_array(&ctxt.get_msg());
    let h: &[u8] = &ctxt_digest.hash()[..8];
    String::from_utf8(ctxt.get_label()).unwrap() + " " + hex::encode_upper(h).as_str()
}

pub struct RpcRequestHandler {
    state_command_sender: tokio::sync::mpsc::Sender<StateUpdateCommand>,
    forwarder_command_sender: tokio::sync::mpsc::Sender<MessageForwarderCommand>,
    outgoing_message_sender: tokio::sync::mpsc::Sender<P2pMessage>,
    incoming_message_sender: tokio::sync::mpsc::Sender<P2pMessage>, // needed only for testing, to "patch" messages received over the RPC Endpoint PushDecryptionShare
}

impl RpcRequestHandler {
    async fn get_decryption_instance(
        &self,
        ciphertext_bytes: &Vec<u8>,
        key_id: &Option<String>,
    ) -> Result<(String, ThresholdCipherProtocol), Status> {
        // Deserialize ciphertext
        let ciphertext = match Ciphertext::deserialize(ciphertext_bytes) {
            Ok(ctxt) => ctxt,
            Err(err) => {
                return Err(Status::new(
                    Code::InvalidArgument,
                    format!("Could not deserialize ciphertext. Err: {:?}", err),
                ));
            }
        };

        // Create a unique instance_id for this instance
        let instance_id = assign_decryption_instance_id(&ciphertext);

        // Check whether an instance with this instance_id already exists
        let (response_sender, response_receiver) = oneshot::channel::<InstanceStatus>();
        let cmd = StateUpdateCommand::GetInstanceStatus {
            instance_id: instance_id.clone(),
            responder: response_sender,
        };
        self.state_command_sender
            .send(cmd)
            .await
            .expect("Receiver for state_command_sender closed.");
        let status = response_receiver
            .await
            .expect("response_receiver.await returned Err");
        if status.started {
            println!(
                ">> REQH: A request with the same id already exists. Instance_id: {:?}",
                instance_id
            );
            return Err(Status::new(
                Code::AlreadyExists,
                format!("A similar request with request_id {instance_id} already exists."),
            ));
        }

        // Retrieve private key for this instance
        let key: Arc<Key>;
        if let Some(_) = key_id {
            unimplemented!(">> REQH: Using specific key by specifying its id not yet supported.")
        } else {
            let (response_sender, response_receiver) =
                oneshot::channel::<Result<Arc<Key>, String>>();
            let cmd = StateUpdateCommand::GetPrivateKeyByType {
                scheme: ciphertext.get_scheme(),
                group: *ciphertext.get_group(),
                responder: response_sender,
            };
            self.state_command_sender
                .send(cmd)
                .await
                .expect("Receiver for state_command_sender closed.");
            let key_result = response_receiver
                .await
                .expect("response_receiver.await returned Err");
            match key_result {
                Ok(key_entry) => key = key_entry,
                Err(err) => return Err(Status::new(Code::InvalidArgument, err)),
            };
        };
        println!(
            ">> REQH: Using key with id: {:?} for request {:?}",
            key.id, &instance_id
        );

        // Initiate the state of the new instance.
        let cmd = StateUpdateCommand::AddNewInstance {
            instance_id: instance_id.clone(),
        };
        self.state_command_sender
            .send(cmd)
            .await
            .expect("Receiver for state_command_sender closed.");

        // Inform the MessageForwarder that a new instance is starting. The MessageForwarder will return a receiver end that the instnace can use to recieve messages.
        let (response_sender, response_receiver) =
            oneshot::channel::<tokio::sync::mpsc::Receiver<Vec<u8>>>();
        let cmd = MessageForwarderCommand::GetReceiverForNewInstance {
            instance_id: instance_id.clone(),
            responder: response_sender,
        };
        self.forwarder_command_sender
            .send(cmd)
            .await
            .expect("Receiver for forwarder_command_sender closed.");
        let receiver_for_new_instance = response_receiver
            .await
            .expect("The sender for response_receiver dropped before sending a response.");

        // Create the new protocol instance
        let prot = ThresholdCipherProtocol::new(
            key,
            ciphertext,
            receiver_for_new_instance,
            self.outgoing_message_sender.clone(),
            instance_id.clone(),
        );
        Ok((instance_id, prot))
    }

    async fn update_decryption_instance_result(
        instance_id: String,
        result: Result<Vec<u8>, ProtocolError>,
        state_command_sender: Sender<StateUpdateCommand>,
        forwarder_command_sender: Sender<MessageForwarderCommand>,
    ) {
        // Update the StateManager with the result of the instance.
        let new_status = InstanceStatus {
            started: true,
            finished: true,
            result,
        };
        let cmd = StateUpdateCommand::UpdateInstanceStatus {
            instance_id: instance_id.clone(),
            new_status,
        };
        state_command_sender
            .send(cmd)
            .await
            .expect("The receiver for state_command_sender has been closed.");

        // Inform MessageForwarder that the instance was terminated.
        let cmd = MessageForwarderCommand::RemoveReceiverForInstance { instance_id };
        forwarder_command_sender
            .send(cmd)
            .await
            .expect("The receiver for forwarder_command_sender has been closed.");
    }
}

#[tonic::async_trait]
impl ThresholdCryptoLibrary for RpcRequestHandler {
    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptReponse>, Status> {
        println!(">> REQH: Received a decrypt request.");
        let req: &DecryptRequest = request.get_ref();

        // Make all required checks and create the new protocol instance
        let (instance_id, mut prot) = match self
            .get_decryption_instance(&req.ciphertext, &req.key_id)
            .await
        {
            Ok((instance_id, prot)) => (instance_id, prot),
            Err(err) => return Err(err),
        };

        // Start it in a new thread, so that the client does not block until the protocol is finished.
        let state_command_sender2 = self.state_command_sender.clone();
        let forwarder_command_sender2 = self.forwarder_command_sender.clone();
        let instance_id2 = instance_id.clone();
        tokio::spawn(async move {
            let result = prot.run().await;

            // Protocol terminated, update state with the result.
            println!(
                ">> REQH: Received result from protocol with instance_id: {:?}",
                instance_id2
            );
            RpcRequestHandler::update_decryption_instance_result(
                instance_id2.clone(),
                result,
                state_command_sender2,
                forwarder_command_sender2,
            )
            .await;
        });

        Ok(Response::new(DecryptReponse {
            instance_id: instance_id.clone(),
        }))
    }

    async fn decrypt_sync(
        &self,
        request: Request<DecryptSyncRequest>,
    ) -> Result<Response<DecryptSyncReponse>, Status> {
        println!(">> REQH: Received a decrypt_sync request.");
        let req: &DecryptSyncRequest = request.get_ref();

        // Do all required checks and create the new protocol instance
        let (instance_id, mut prot) = match self
            .get_decryption_instance(&req.ciphertext, &req.key_id)
            .await
        {
            Ok((instance_id, prot)) => (instance_id, prot),
            Err(err) => return Err(err),
        };

        // Start the new protocol instance
        let result: Result<Vec<u8>, ProtocolError> = prot.run().await;

        // Protocol terminated, update state with the result.
        println!(
            ">> REQH: Received result from protocol with instance_id: {:?}",
            instance_id
        );

        RpcRequestHandler::update_decryption_instance_result(
            instance_id.clone(),
            result.clone(),
            self.state_command_sender.clone(),
            self.forwarder_command_sender.clone(),
        )
        .await;

        // todo: Return the error here
        let return_result = match result {
            Ok(res) => Some(res),
            Err(_) => None,
        };
        Ok(Response::new(DecryptSyncReponse {
            instance_id: instance_id.clone(),
            plaintext: return_result,
        }))
    }

    async fn get_public_keys_for_encryption(
        &self,
        request: Request<GetPublicKeysForEncryptionRequest>,
    ) -> Result<Response<GetPublicKeysForEncryptionResponse>, Status> {
        println!(">> REQH: Received a get_public_keys_for_encryption request.");
        let (response_sender, response_receiver) = oneshot::channel::<Vec<Arc<Key>>>();
        let cmd = StateUpdateCommand::GetEncryptionKeys {
            responder: response_sender,
        };
        self.state_command_sender
            .send(cmd)
            .await
            .expect("Receiver for state_command_sender closed.");
        let key_entries = response_receiver
            .await
            .expect("response_receiver.await returned Err");
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
        Ok(Response::new(GetPublicKeysForEncryptionResponse {
            keys: public_keys,
        }))
    }

    async fn get_decrypt_result(
        &self,
        request: Request<GetDecryptResultRequest>,
    ) -> Result<Response<GetDecryptResultResponse>, Status> {
        println!(">> REQH: Received a get_decrypt_result request.");
        let req: &GetDecryptResultRequest = request.get_ref();

        // Get status of the instance by contacting the state manager
        let (response_sender, response_receiver) = oneshot::channel::<InstanceStatus>();
        let cmd = StateUpdateCommand::GetInstanceStatus {
            instance_id: req.instance_id.clone(),
            responder: response_sender,
        };
        self.state_command_sender
            .send(cmd)
            .await
            .expect("Receiver for state_command_sender closed.");
        let status = response_receiver
            .await
            .expect("response_receiver.await returned Err");

        let mut result = None;
        if status.finished {
            if let Ok(res) = status.result {
                result = Some(res)
            };
        };
        let response = GetDecryptResultResponse {
            instance_id: req.instance_id.clone(),
            is_started: status.started,
            is_finished: status.finished,
            plaintext: result,
        };
        Ok(Response::new(response))
    }

    // Meant only for testing. In real depolyments decryption shares are sent through a separate libP2P-based network.
    async fn push_decryption_share(
        &self,
        request: Request<PushDecryptionShareRequest>,
    ) -> Result<Response<PushDecryptionShareResponse>, Status> {
        let req = request.get_ref();
        // println!(">> NET: Received a decryption share. Instance_id: {:?}. Pushing to net_to_demult channel,", req.instance_id);
        let p2p_message = P2pMessage {
            instance_id: req.instance_id.clone(),
            message_data: req.decryption_share.clone(),
        };
        self.incoming_message_sender
            .send(p2p_message)
            .await
            .unwrap();
        Ok(Response::new(PushDecryptionShareResponse {}))
    }
}

pub async fn init(
    rpc_listen_address: String,
    rpc_listen_port: u32,
    keychain: KeyChain,
    incoming_message_receiver: tokio::sync::mpsc::Receiver<P2pMessage>,
    outgoing_message_sender: tokio::sync::mpsc::Sender<P2pMessage>,
    incoming_message_sender: tokio::sync::mpsc::Sender<P2pMessage>, // needed only for testing, to "patch" messages received over the RPC Endpoint PushDecryptionShare
) {
    // Channel to send commands to the StateManager. There are two places in the code such a command can be sent from:
    // - The RpcRequestHandler, when a new request is received (it takes ownership state_command_sender2)
    // - The MessageForwarder, when it wants to know whether an instance has already finished (takes ownership of state_command_sender)
    // The channel must never be closed.
    let (state_command_sender, state_command_receiver) =
        tokio::sync::mpsc::channel::<StateUpdateCommand>(32);
    let state_command_sender2 = state_command_sender.clone();

    // Channel to send commands to the MessageForwarder.
    // The sender end is owned by the RpcRequestHandler and must never be closed.
    let (forwarder_command_sender, forwarder_command_receiver) =
        tokio::sync::mpsc::channel::<MessageForwarderCommand>(32);

    // Spawn StateManager.
    // Takes ownerhsip of keychain and state_command_receiver
    println!(">> REQH: Initiating the state manager.");
    tokio::spawn(async move {
        let mut sm = StateManager::new(keychain, state_command_receiver);
        sm.run().await;
    });

    // Spawn MessageForwarder
    // Takes ownershiip of forwarder_command_receiver, incoming_message_receiver, state_command_sender
    println!(">> REQH: Initiating MessageForwarder.");
    tokio::spawn(async move {
        let mut mfw = MessageForwarder::new(
            forwarder_command_receiver,
            incoming_message_receiver,
            state_command_sender,
        );
        mfw.run().await;
    });

    // Start server
    let rpc_addr = format!("{}:{}", rpc_listen_address, rpc_listen_port);
    println!(">> REQH: Request handler is starting. Listening for RPC on address: {rpc_addr}");
    let service = RpcRequestHandler {
        state_command_sender: state_command_sender2,
        forwarder_command_sender,
        outgoing_message_sender,
        // result_sender,
        incoming_message_sender,
    };
    Server::builder()
        .add_service(ThresholdCryptoLibraryServer::new(service))
        // .serve(format!("[{rpc_listen_address}]:{rpc_listen_port}").parse().unwrap())
        .serve(rpc_addr.parse().unwrap())
        .await
        .expect("");
}
