use std::borrow::BorrowMut;
use std::sync::Arc;
use theta_network::config::static_net;
use rand::Rng;
use rand::distributions::Alphanumeric;
use theta_schemes::scheme_types_impl::{SchemeDetails, GroupDetails};
use theta_proto::protocol_types::threshold_crypto_library_client::ThresholdCryptoLibraryClient;
use theta_proto::protocol_types::{CoinRequest, CoinResponse, GetSignatureResultRequest, GetSignatureResultResponse, GetCoinResultResponse, GetCoinResultRequest};
use theta_proto::scheme_types::Group;
use tokio::sync::{mpsc::Sender, oneshot};
use tonic::Code;
use tonic::{transport::Server, Request, Response, Status};
use std::str;

use mcore::hash256::HASH256;
use theta_network::types::message::NetMessage;
use theta_schemes::interface::{Ciphertext, Serializable, Signature, ThresholdScheme, ThresholdCoin, InteractiveThresholdSignature};
use theta_proto::protocol_types::{
    threshold_crypto_library_server::{ThresholdCryptoLibrary, ThresholdCryptoLibraryServer},
    DecryptResponse, DecryptRequest, SignRequest, SignResponse,
    GetDecryptResultRequest, GetDecryptResultResponse, GetPublicKeysForEncryptionRequest,
    GetPublicKeysForEncryptionResponse, PublicKeyEntry, PushDecryptionShareRequest,
    PushDecryptionShareResponse,
};

use theta_protocols::threshold_cipher::protocol::ThresholdCipherProtocol;
use theta_protocols::threshold_signature::protocol::{ThresholdSignatureProtocol, ThresholdSignaturePrecomputation};
use theta_protocols::threshold_coin::protocol::ThresholdCoinProtocol;
use theta_orchestration::{
    keychain::KeyChain,
    message_dispatcher::{MessageDispatcher, MessageDispatcherCommand},
    state_manager::{InstanceStatus, StateManager, StateUpdateCommand},
    types::{Key, ProtocolError},
};

const NUM_PRECOMPUTATIONS:i32 = 3;


fn assign_decryption_instance_id(ctxt: &Ciphertext) -> String {
    String::from_utf8(ctxt.get_label()).unwrap()
}

fn assign_signature_instance_id(message: &[u8], label: &[u8]) -> String {
    let mut ctxt_digest = HASH256::new();
    ctxt_digest.process_array(message);
    let h: &[u8] = &ctxt_digest.hash()[..8];
    String::from_utf8(label.to_vec()).unwrap() + " " + hex::encode_upper(h).as_str()
}

fn assign_coin_instance_id(name: &[u8]) -> String {
    String::from_utf8(name.to_vec()).unwrap()
}

pub struct RpcRequestHandler {
    state_command_sender: tokio::sync::mpsc::Sender<StateUpdateCommand>,
    dispatcher_command_sender: tokio::sync::mpsc::Sender<MessageDispatcherCommand>,
    outgoing_message_sender: tokio::sync::mpsc::Sender<NetMessage>,
    incoming_message_sender: tokio::sync::mpsc::Sender<NetMessage>, // needed only for testing, to "patch" messages received over the RPC Endpoint PushDecryptionShare
    frost_precomputations: Vec<InteractiveThresholdSignature>,
    my_id: u32,
    config: static_net::deserialize::Config
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

        // Inform the MessageDispatcher that a new instance is starting.
        // The MessageDispatcher (responsible for maintaining a channel to each protocol instance)
        // creates a channel to forward messages to the new instance, keeps the sender end of that channel,
        // and returns the receiver end to the RPC handler.
        // This receiver end is then given to the instance, so it can poll it and receive incoming messages.
        let (response_sender, response_receiver) =
            oneshot::channel::<tokio::sync::mpsc::Receiver<Vec<u8>>>();
        let cmd = MessageDispatcherCommand::InsertInstance {
            instance_id: instance_id.clone(),
            responder: response_sender,
        };
        self.dispatcher_command_sender
            .send(cmd)
            .await
            .expect("Receiver for dispatcher_command_sender closed.");
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

    async fn pop_frost_precomputation(&self) -> Option<InteractiveThresholdSignature> {
        let precomputation: InteractiveThresholdSignature;

        let (response_sender, response_receiver) =
            oneshot::channel::<Option<InteractiveThresholdSignature>>();
        let cmd = StateUpdateCommand::PopFrostPrecomputation { responder: response_sender };
        self.state_command_sender
            .send(cmd)
            .await
            .expect("Receiver for state_command_sender closed.");
        let result = response_receiver
            .await
            .expect("response_receiver.await returned Err");
        match result {
            Some(precomp) => return Some(precomp),
            None => return None,
        };
    }

    async fn push_frost_precomputation(
        state_command_sender: Sender<StateUpdateCommand>,
        instance: InteractiveThresholdSignature) -> Result<(), ()> {
        let precomputation: Arc<InteractiveThresholdSignature>;

        let (response_sender, response_receiver) =
            oneshot::channel::<Option<InteractiveThresholdSignature>>();
        let cmd = StateUpdateCommand::PushFrostPrecomputation { instance: instance };
        state_command_sender
            .send(cmd)
            .await
            .expect("Receiver for state_command_sender closed.");

        return Ok(());
    }

    async fn get_signature_instance(
        &self,
        message: Option<&Vec<u8>>,
        label: &Vec<u8>,
        key_id: &Option<String>,
        scheme_id: u8,
        group_id: u8,
        instance: Option<InteractiveThresholdSignature>
    ) -> Result<(String, ThresholdSignatureProtocol), Status> {
        let instance_id;
        if message.is_none() {
            let s = match str::from_utf8(label) {
                Ok(v) => v,
                Err(e) => return Err(Status::aborted("error decoding label")),
            };
            instance_id = String::from(s);
        } else {
            instance_id = assign_signature_instance_id(&message.unwrap(), &label);
        }

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
                scheme: ThresholdScheme::from_id(scheme_id).unwrap(),
                group: Group::from_code(group_id).unwrap(),
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

        // Inform the MessageDispatcher that a new instance is starting. The MessageDispatcher will return a receiver end that the instnace can use to recieve messages.
        let (response_sender, response_receiver) =
            oneshot::channel::<tokio::sync::mpsc::Receiver<Vec<u8>>>();
        let cmd = MessageDispatcherCommand::InsertInstance {
            instance_id: instance_id.clone(),
            responder: response_sender,
        };
        self.dispatcher_command_sender
            .send(cmd)
            .await
            .expect("Receiver for dispatcher_command_sender closed.");
        let receiver_for_new_instance = response_receiver
            .await
            .expect("The sender for response_receiver dropped before sending a response.");

        let prot;
        if instance.is_none() {
            // Create the new protocol instance
            prot = ThresholdSignatureProtocol::new(
                key,
                message,
                label,
                receiver_for_new_instance,
                self.outgoing_message_sender.clone(),
                instance_id.clone(),
            );
        } else {
            // Create the new protocol instance
            prot = ThresholdSignatureProtocol::from_instance(
                &instance.unwrap(),
                key,
                message.unwrap(),
                label,
                receiver_for_new_instance,
                self.outgoing_message_sender.clone(),
                instance_id.clone(),
            );
        }
        

        Ok((instance_id, prot))
    }

    async fn get_precompute_instance(
        &self,
        label: &Vec<u8>,
        key_id: &Option<String>,
        scheme_id: u8,
        group_id: u8
    ) -> Result<(String, ThresholdSignaturePrecomputation), Status> {
        let instance_id;
      
        let s = match str::from_utf8(label) {
            Ok(v) => v,
            Err(e) => return Err(Status::aborted("error decoding label")),
        };
        instance_id = String::from(s);
    
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
                scheme: ThresholdScheme::from_id(scheme_id).unwrap(),
                group: Group::from_code(group_id).unwrap(),
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

        // Inform the MessageDispatcher that a new instance is starting. The MessageDispatcher will return a receiver end that the instnace can use to recieve messages.
        let (response_sender, response_receiver) =
            oneshot::channel::<tokio::sync::mpsc::Receiver<Vec<u8>>>();
        let cmd = MessageDispatcherCommand::InsertInstance {
            instance_id: instance_id.clone(),
            responder: response_sender,
        };
        self.dispatcher_command_sender
            .send(cmd)
            .await
            .expect("Receiver for dispatcher_command_sender closed.");
        let receiver_for_new_instance = response_receiver
            .await
            .expect("The sender for response_receiver dropped before sending a response.");

        // Create the new protocol instance
        let prot = ThresholdSignaturePrecomputation::new(
            key,
            label,
            receiver_for_new_instance,
            self.outgoing_message_sender.clone(),
            instance_id.clone(),
        );

        Ok((instance_id, prot))
    }

    async fn get_coin_instance(
        &self,
        name: &Vec<u8>,
        key_id: &Option<String>,
        scheme_id: u8,
        group_id: u8
    ) -> Result<(String, ThresholdCoinProtocol), Status> {
        // Create a unique instance_id for this instance
        let instance_id = assign_coin_instance_id(&name);

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
                scheme: ThresholdScheme::from_id(scheme_id).unwrap(),
                group: Group::from_code(group_id).unwrap(),
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

        // Inform the MessageDispatcher that a new instance is starting. The MessageDispatcher will return a receiver end that the instnace can use to recieve messages.
        let (response_sender, response_receiver) =
            oneshot::channel::<tokio::sync::mpsc::Receiver<Vec<u8>>>();
        let cmd = MessageDispatcherCommand::InsertInstance {
            instance_id: instance_id.clone(),
            responder: response_sender,
        };
        self.dispatcher_command_sender
            .send(cmd)
            .await
            .expect("Receiver for dispatcher_command_sender closed.");
        let receiver_for_new_instance = response_receiver
            .await
            .expect("The sender for response_receiver dropped before sending a response.");

        // Create the new protocol instance
        let prot = ThresholdCoinProtocol::new(
            key,
            name,
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
        dispatcher_command_sender: Sender<MessageDispatcherCommand>,
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

        // Inform MessageDispatcher that the instance was terminated.
        let cmd = MessageDispatcherCommand::RemoveInstance { instance_id };
        dispatcher_command_sender
            .send(cmd)
            .await
            .expect("The receiver for dispatcher_command_sender has been closed.");
    }

    async fn update_signature_instance_result(
        instance_id: String,
        result: Result<Signature, ProtocolError>,
        state_command_sender: Sender<StateUpdateCommand>,
        dispatcher_command_sender: Sender<MessageDispatcherCommand>,
    ) {

        let r;
        if result.is_err(){
            r = Err(result.unwrap_err());
        } else {
            r = Ok(result.unwrap().serialize().unwrap());
        }

        // Update the StateManager with the result of the instance.
        let new_status = InstanceStatus {
            started: true,
            finished: true,
            result:r,
        };
        let cmd = StateUpdateCommand::UpdateInstanceStatus {
            instance_id: instance_id.clone(),
            new_status,
        };
        state_command_sender
            .send(cmd)
            .await
            .expect("The receiver for state_command_sender has been closed.");

        // Inform MessageDispatcher that the instance was terminated.
        let cmd = MessageDispatcherCommand::RemoveInstance { instance_id };
        dispatcher_command_sender
            .send(cmd)
            .await
            .expect("The receiver for dispatcher_command_sender has been closed.");
    }

    async fn update_coin_instance_result(
        instance_id: String,
        result: Result<u8, ProtocolError>,
        state_command_sender: Sender<StateUpdateCommand>,
        dispatcher_command_sender: Sender<MessageDispatcherCommand>,
    ) {

        let r;
        if result.is_err(){
            r = Err(result.unwrap_err());
        } else {
            r = Ok(vec![result.unwrap()]);
        }

        // Update the StateManager with the result of the instance.
        let new_status = InstanceStatus {
            started: true,
            finished: true,
            result:r,
        };
        let cmd = StateUpdateCommand::UpdateInstanceStatus {
            instance_id: instance_id.clone(),
            new_status,
        };
        state_command_sender
            .send(cmd)
            .await
            .expect("The receiver for state_command_sender has been closed.");

        // Inform MessageDispatcher that the instance was terminated.
        let cmd = MessageDispatcherCommand::RemoveInstance { instance_id };
        dispatcher_command_sender
            .send(cmd)
            .await
            .expect("The receiver for dispatcher_command_sender has been closed.");
    }

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
        let dispatcher_command_sender2 = self.dispatcher_command_sender.clone();
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
}

#[tonic::async_trait]
impl ThresholdCryptoLibrary for RpcRequestHandler {
    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        println!(">> REQH: Received a decrypt request.");
        let req: &DecryptRequest = request.get_ref();

        // Make all required checks and create the new protocol instance
        let (instance_id, mut prot): (String, ThresholdCipherProtocol) = match self
            .get_decryption_instance(&req.ciphertext, &req.key_id)
            .await
        {
            Ok((instance_id, prot)) => (instance_id, prot),
            Err(err) => return Err(err),
        };

        // Start it in a new thread, so that the client does not block until the protocol is finished.
        let state_command_sender2 = self.state_command_sender.clone();
        let dispatcher_command_sender2 = self.dispatcher_command_sender.clone();
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
                dispatcher_command_sender2,
            )
            .await;
        });

        Ok(Response::new(DecryptResponse {
            instance_id: instance_id.clone(),
        }))
    }

    /* this method is called in the case of atomic broadcast */
    async fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        return self.do_sign(request).await;
    }

    async fn flip_coin(
        &self,
        request: Request<CoinRequest>,
    ) -> Result<Response<CoinResponse>, Status> {
        println!(">> REQH: Received a coin flip request.");
        let req: &CoinRequest = request.get_ref();

        // Make all required checks and create the new protocol instance
        let (instance_id, mut prot) = match self
            .get_coin_instance(&req.name, &req.key_id, req.scheme as u8, req.group as u8)
            .await
        {
            Ok((instance_id, prot)) => (instance_id, prot),
            Err(err) => return Err(err),
        };

        // Start it in a new thread, so that the client does not block until the protocol is finished.
        let state_command_sender2 = self.state_command_sender.clone();
        let dispatcher_command_sender2 = self.dispatcher_command_sender.clone();
        let instance_id2 = instance_id.clone();
        tokio::spawn(async move {
            let result = prot.run().await;

            // Protocol terminated, update state with the result.
            println!(
                ">> REQH: Received result from protocol with instance_id: {:?}",
                instance_id2
            );
            RpcRequestHandler::update_coin_instance_result(
                instance_id2.clone(),
                result,
                state_command_sender2,
                dispatcher_command_sender2,
            )
            .await;
        });

        Ok(Response::new(CoinResponse {
            instance_id: instance_id.clone(),
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

 
    async fn get_signature_result(
        &self,
        request: Request<GetSignatureResultRequest>,
    ) -> Result<Response<GetSignatureResultResponse>, Status> {
        println!(">> REQH: Received a get_signature_result request.");
        let req: &GetSignatureResultRequest = request.get_ref();

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
        let response = GetSignatureResultResponse {
            instance_id: req.instance_id.clone(),
            is_started: status.started,
            is_finished: status.finished,
            signature: result,
        };
        Ok(Response::new(response))
    }

    async fn get_coin_result(
        &self,
        request: Request<GetCoinResultRequest>,
    ) -> Result<Response<GetCoinResultResponse>, Status> {
        println!(">> REQH: Received a get_coin_result request.");
        let req: &GetCoinResultRequest = request.get_ref();

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

        let mut coin = Option::None;

        if result.is_some() {
            let r = result.unwrap()[0] as i32;
            coin  = Option::Some(r);
        }

        let response = GetCoinResultResponse {
            instance_id: req.instance_id.clone(),
            is_started: status.started,
            is_finished: status.finished,
            coin: coin,
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
        let p2p_message = NetMessage {
            instance_id: req.instance_id.clone(),
            is_total_order: false,
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
    rpc_listen_port: u16,
    keychain: KeyChain,
    incoming_message_receiver: tokio::sync::mpsc::Receiver<NetMessage>,
    outgoing_message_sender: tokio::sync::mpsc::Sender<NetMessage>,
    incoming_message_sender: tokio::sync::mpsc::Sender<NetMessage>, // needed only for testing, to "patch" messages received over the RPC Endpoint PushDecryptionShare
    config: static_net::deserialize::Config,
    my_id: u32 
) {
    // Channel to send commands to the StateManager.
    // Used by the RpcRequestHandler, when a new request is received (it takes ownership state_command_sender)
    // The channel must never be closed.
    let (state_command_sender, state_command_receiver) =
        tokio::sync::mpsc::channel::<StateUpdateCommand>(32);

    // Channel to send commands to the MessageDispatcher.
    // The sender end is owned by the RpcRequestHandler and must never be closed.
    let (dispatcher_command_sender, dispatcher_command_receiver) =
        tokio::sync::mpsc::channel::<MessageDispatcherCommand>(32);

    // Spawn StateManager.
    // Takes ownerhsip of keychain and state_command_receiver
    println!(">> REQH: Initiating the state manager.");
    tokio::spawn(async move {
        let mut sm = StateManager::new(keychain, state_command_receiver);
        sm.run().await;
    });

    // Spawn MessageDispatcher
    // Takes ownershiip of dispatcher_command_receiver, incoming_message_receiver, state_command_sender
    println!(">> REQH: Initiating MessageDispatcher.");
    tokio::spawn(async move {
        let mut mfw = MessageDispatcher::new(dispatcher_command_receiver, incoming_message_receiver);
        mfw.run().await;
    });

    // Start server
    let rpc_addr = format!("{}:{}", rpc_listen_address, rpc_listen_port);
    let service = RpcRequestHandler {
        state_command_sender,
        dispatcher_command_sender,
        outgoing_message_sender,
        incoming_message_sender,
        frost_precomputations: Vec::new(),
        my_id,
        config
    };
    Server::builder()
        .add_service(ThresholdCryptoLibraryServer::new(service))
        // .serve(format!("[{rpc_listen_address}]:{rpc_listen_port}").parse().unwrap())
        .serve(rpc_addr.parse().unwrap())
        .await
        .expect("");
    println!(">> REQH: Request handler is starting. Listening for RPC on address: {rpc_addr}");
}
