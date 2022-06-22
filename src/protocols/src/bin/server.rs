use mcore::hash256::HASH256;
use protocols::keychain::KeyChain;
use protocols::pb;
use protocols::pb::requests::threshold_crypto_library_server::{ThresholdCryptoLibrary,ThresholdCryptoLibraryServer};
use protocols::pb::requests::{ThresholdDecryptionRequest, ThresholdDecryptionResponse, self, PushDecryptionShareRequest, PushDecryptionShareResponse};
use cosmos_crypto::dl_schemes::dl_groups::dl_group::DlGroup;
use cosmos_crypto::interface::{ThresholdCipherParams, Ciphertext, Serializable};
use cosmos_crypto::rand::{RNG, RngAlgorithm};
use protocols::rpc_network::RpcNetwork;
use protocols::state_manager::{StateUpdateCommand, StateManager};
use rand::prelude::SliceRandom;
use rand::thread_rng;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::oneshot;
use tonic::{transport::Server, Request, Response, Status};
use std::convert::TryInto;
use std::env;
use std::fs::{File, self};
use std::str::from_utf8;
use std::sync::mpsc::Receiver;
use std::{collections::HashSet, thread, sync::mpsc};
use cosmos_crypto::{dl_schemes::{ciphers::{sg02::{Sg02PublicKey, Sg02PrivateKey, Sg02ThresholdCipher, Sg02Ciphertext}, bz03::{Bz03ThresholdCipher, Bz03PrivateKey, Bz03PublicKey, Bz03Ciphertext}}, dl_groups::bls12381::Bls12381}, interface::{ThresholdCipher, PublicKey, PrivateKey, Share}};
use protocols::threshold_cipher_protocol::{ThresholdCipherProtocol, Protocol};
use std::collections::{self, HashMap};
use serde::{Serialize, Deserialize};
use std::str::FromStr;

fn assign_decryption_instance_id(ctxt: &impl Ciphertext) -> String {
    let mut ctxt_digest = HASH256::new();
    ctxt_digest.process_array(&ctxt.get_msg());
    let h: &[u8] = &ctxt_digest.hash()[..8];
    String::from_utf8(ctxt.get_label()).unwrap() + " " + &hex::encode_upper(h)
}
pub struct Context {
    key_chain: KeyChain,
}


// #[derive(Debug, Default)]
pub struct RequestHandler {
    context: Context,
    state_manager_sender: tokio::sync::mpsc::Sender<StateUpdateCommand>,
}


impl RequestHandler{
    async fn start_decryption_instance<C: ThresholdCipher>(&self, 
                                                           req: ThresholdDecryptionRequest,
                                                           sk: C::TPrivKey,
                                                           pk: C::TPubKey) 
                                                        -> Result<Response<ThresholdDecryptionResponse>, Status>
        where <C as cosmos_crypto::interface::ThresholdCipher>::TPrivKey: Send + 'static,
            <C as cosmos_crypto::interface::ThresholdCipher>::TPubKey: Send + 'static,
            <C as cosmos_crypto::interface::ThresholdCipher>::TShare: Send + 'static + Sync,
            <C as cosmos_crypto::interface::ThresholdCipher>::CT: Send + 'static,
            C: 'static
    {
        let ciphertext = match C::CT::deserialize(&req.ciphertext) {
            Ok(ctxt) => ctxt,
            Err(_) =>  {
                println!(">> RH: ERROR: Failed to deserialize ciphertext in request.");
                return Err(Status::new(tonic::Code::InvalidArgument, "Failed to deserialize ciphertext."))
            }
        };
        let instance_id = assign_decryption_instance_id(&ciphertext);
        
        // Check whether an instance with this instance_id already exists
        let (responder_sender, responder_receiver) = oneshot::channel::<bool>();
        let cmd = StateUpdateCommand::GetInstanceIdExists { instance_id: instance_id.clone(), responder: responder_sender };
        self.state_manager_sender.send(cmd).await.unwrap();
        match responder_receiver.await{
            Ok(exists) => {
                if exists {
                     println!(">> RH: A request with the same id already exists. Instance_id: {:?}", instance_id);
                     return Err(Status::new(tonic::Code::AlreadyExists, format!("A similar request with request_id {instance_id} already exists")))
                 }
            },
            Err(_) => {
                println!(">> RH: ERROR: Could not start decryption instance. responder_sender was dropped. Instance_id: {:?}", instance_id);
                return Err(Status::new(tonic::Code::Internal, "Could not start decryption instance: responder_sender was dropped"))
            },
        }
        // Add this instance_id to state
        let cmd = StateUpdateCommand::AddInstanceId { instance_id: instance_id.clone()};
        self.state_manager_sender.send(cmd).await.unwrap();

        // Create a channel for network-to-protocol communication, one for protocol-to-network communication,
        // and one for the protocol-to-state-manager communication, where the result will be returned.
        let (net_to_prot_sender, net_to_prot_receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let (prot_to_net_sender, prot_to_net_receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let (result_sender, result_receiver) = tokio::sync::mpsc::channel::<Option<Vec<u8>>>(32);
        
        // Update the state. We need to keep the sender end of net_to_prot channel, the receiver end of prot_to_net, 
        // and the reciever end of the protocol-to-state-manager channel. The state manager takes ownership.
        let cmd = StateUpdateCommand::AddNetToProtChannel { instance_id: instance_id.clone(), sender: net_to_prot_sender };
        self.state_manager_sender.send(cmd).await.unwrap();
        let cmd = StateUpdateCommand::AddProtToNetChannel { instance_id: instance_id.clone(), receiver: prot_to_net_receiver };
        self.state_manager_sender.send(cmd).await.unwrap();
        let cmd = StateUpdateCommand::AddResultChannel { instance_id: instance_id.clone(), receiver: result_receiver };
        self.state_manager_sender.send(cmd).await.unwrap();
        
        // The receiver end of net_to_prot channel, the sender end of prot_to_net,
        // and the sener end of the protocol-to-state-manage channel are given to the protocol. The protocol takes ownership.
        let mut prot = ThresholdCipherProtocol::<C>::new(
            sk.clone(),
            pk.clone(),
            ciphertext,
            net_to_prot_receiver,
            prot_to_net_sender,
            result_sender,
            instance_id.clone()
        );
        
        // Start the new protocol instance as a new tokio task
        println!(">> RH: Spawning new protocol instance with instance_id: {:?}", &instance_id);
        tokio::spawn( async move {
            prot.run().await; 
        });

        Ok(Response::new(requests::ThresholdDecryptionResponse { instance_id }))
    }
}

#[tonic::async_trait]
impl ThresholdCryptoLibrary for RequestHandler {
    
    async fn decrypt(&self, request: Request<ThresholdDecryptionRequest>) -> Result<Response<ThresholdDecryptionResponse>, Status> {
        let req = request.get_ref();
        println!(">> RH: Received a decryption request. Key_id: {:?}", req.key_id);
        
        let req_scheme = requests::ThresholdCipher::from_i32(req.algorithm).unwrap();
        let req_domain = requests::DlGroup::from_i32(req.dl_group).unwrap();
        let key = self.context.key_chain.get_key(req_scheme, req_domain, None);
        if let Err(err) = key {
            return Err(Status::new(tonic::Code::InvalidArgument, "Key"))
        }
        let serialized_key = key.unwrap();

        // todo: implement these enums in cosmos_crypto library, not in proto
        // todo: The reason we retrieve the pk here (and not inside the protocol instance) is because of the ThresholdCipher::TPrivKey vs PrivateKey::TPrivKey compiler error.
        match (req_scheme, req_domain) {
            (requests::ThresholdCipher::Sg02, requests::DlGroup::Bls12381)  => {
                let sk = Sg02PrivateKey::<Bls12381>::deserialize(&serialized_key).unwrap();
                let pk = sk.get_public_key();                
                self.start_decryption_instance::<Sg02ThresholdCipher<Bls12381>>(req.clone(), sk, pk).await
            },
            (requests::ThresholdCipher::Bz02, requests::DlGroup::Bls12381) => {
                let sk = Bz03PrivateKey::<Bls12381>::deserialize(&serialized_key).unwrap();
                let pk = sk.get_public_key();
                self.start_decryption_instance::<Bz03ThresholdCipher<Bls12381>>(req.clone(), sk, pk).await
            },
            (_, _) => {
                Err(Status::new(tonic::Code::InvalidArgument, "Requested scheme and domain."))
            }
        }
    }

    async fn push_decryption_share(&self, request: Request<PushDecryptionShareRequest>) -> Result<Response<PushDecryptionShareResponse>, Status> {
        let req = request.get_ref();
        println!(">> RH: Received a decryption share. Instance_id: {:?}", req.instance_id);
        
        let (responder_sender, responder_receiver) = oneshot::channel::<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>();
        let cmd = StateUpdateCommand::GetNetToProtSender { instance_id: req.instance_id.clone(), responder: responder_sender};
        self.state_manager_sender.send(cmd).await.unwrap();
        match responder_receiver.await{
            Ok(v) => {
                match v {
                    Some(sender) => {
                        println!(">> RH: Pushing decryption share in net_to_prot. Instance_id: {:?}", req.instance_id.clone());
                        if let Err(_) = sender.send(req.decryption_share.clone()).await{ // receiver end has already been closed                            
                            println!(">> RH: Pushing decryption share FAILED. Maybe thread already finished? Instance_id: {:?}", req.instance_id.clone());
                        }
                        Ok(Response::new(requests::PushDecryptionShareResponse{}))
                    },
                    None => {
                        // todo: Handle this:
                        // instance_id might not exist because the instance has already finished -> That's ok.
                        // But instance_id might not exist because the decryption request has not arrived yet -> Backlog these messages.
                        println!(">> RH: Did not push decryption share in net_to_prot. Protocol already finished. Instance_id: {:?}", req.instance_id.clone());
                        Ok(Response::new(requests::PushDecryptionShareResponse{}))
                    },
                }
            }
            Err(_) => { // responder_sender was dropped
                println!(">> RH: ERROR: Could not push decryption share in net_to_prot. responder_sender was dropped. Instance_id: {:?}", req.instance_id.clone());
                Err(Status::new(tonic::Code::Internal, "Could not handle decryption share: responder_sender was dropped"))
            },
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Please provide server ID.")
    }
    let my_id = u32::from_str(&args[1])?;
    // Init network
    println!(">> RH: Initiating network manager.");
    let network_manager = RpcNetwork::new(my_id).await;

    // Spawn State Manager
    let (state_manager_sender, state_manager_receiver) = tokio::sync::mpsc::channel::<StateUpdateCommand>(32);

    //Demultiplexor
    // thread::spawn( async move {

    // });

    let mut state_manager = StateManager::new(state_manager_receiver, network_manager);
    thread::spawn( move || {
        state_manager.run()
    });
    
    // Read keys from file
    println!(">> RH: Reading keys from keychain.");
    let key_chain: KeyChain = KeyChain::from_file("conf/keys_0.json"); 
    println!(">> RH: Reading keys done");
    
    // Setup the request handler
    let context = Context {
        key_chain
    };

    // Start server
    let addr = "[::1]:50051".parse()?;
    let service = RequestHandler{
        context,
        state_manager_sender,
    };
    
    Server::builder()
        .add_service(ThresholdCryptoLibraryServer::new(service))
        .serve(addr)
        .await?;
    Ok(())
}