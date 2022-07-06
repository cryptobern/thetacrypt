use mcore::hash256::HASH256;
use network::p2p::gossipsub::setup::P2pMessage;
use protocols::keychain::KeyChain;
use protocols::pb;
use protocols::pb::requests::threshold_crypto_library_server::{ThresholdCryptoLibrary,ThresholdCryptoLibraryServer};
use protocols::pb::requests::{ThresholdDecryptionRequest, ThresholdDecryptionResponse, self, PushDecryptionShareRequest, PushDecryptionShareResponse};
use cosmos_crypto::dl_schemes::dl_groups::dl_group::DlGroup;
use cosmos_crypto::interface::{ThresholdCipherParams, Ciphertext, Serializable};
use cosmos_crypto::rand::{RNG, RngAlgorithm};
use protocols::rpc_network::RpcNetwork;
use rand::prelude::SliceRandom;
use rand::thread_rng;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::oneshot;
use tonic::{transport::Server, Request, Response, Status};
use std::convert::TryInto;
use std::{env, result};
use std::fs::{File, self};
use std::str::from_utf8;
use std::sync::mpsc::Receiver;
use std::{collections::HashSet, thread, sync::mpsc};
use cosmos_crypto::{dl_schemes::{ciphers::{sg02::{Sg02PublicKey, Sg02PrivateKey, Sg02ThresholdCipher, Sg02Ciphertext}, bz03::{Bz03ThresholdCipher, Bz03PrivateKey, Bz03PublicKey, Bz03Ciphertext}}, dl_groups::bls12381::Bls12381}, interface::{ThresholdCipher, PublicKey, PrivateKey, Share}};
use protocols::threshold_cipher_protocol::{ThresholdCipherProtocol, Protocol};
use std::collections::{self, HashMap};
use serde::{Serialize, Deserialize};
use std::str::FromStr;

type InstanceId = String;



#[derive(Debug)]
pub enum DemultUpdateCommand {
    AddDemultToProtChannel {
        instance_id: String,
        sender: tokio::sync::mpsc::Sender<Vec<u8>>
    }
}

#[derive(Debug)]
pub enum StateUpdateCommand {
    AddInstanceResult {
        instance_id: String,
        result: Option<Vec<u8>>
    },
    GetInstanceResult {
        instance_id: String,
        responder: tokio::sync::oneshot::Sender< Option<Vec<u8>> >
    },
}

fn assign_decryption_instance_id(ctxt: &impl Ciphertext) -> String {
    let mut ctxt_digest = HASH256::new();
    ctxt_digest.process_array(&ctxt.get_msg());
    let h: &[u8] = &ctxt_digest.hash()[..8];
    String::from_utf8(ctxt.get_label()).unwrap() + " " + hex::encode_upper(h).as_str()
}

pub struct RequestHandler {
    key_chain: KeyChain,
    state_command_sender: tokio::sync::mpsc::Sender<StateUpdateCommand>,
    demult_command_sender: tokio::sync::mpsc::Sender<DemultUpdateCommand>,
    prot_to_net_sender: tokio::sync::mpsc::Sender<P2pMessage>,
    result_sender: tokio::sync::mpsc::Sender<(InstanceId, Option<Vec<u8>>)>,
    net_to_demult_sender: tokio::sync::mpsc::Sender<P2pMessage>, //temp
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
                println!(">> REQH: ERROR: Failed to deserialize ciphertext in request.");
                return Err(Status::new(tonic::Code::InvalidArgument, "Failed to deserialize ciphertext."))
            }
        };
        let instance_id = assign_decryption_instance_id(&ciphertext);
        
        // Check whether an instance with this instance_id already exists
        let (response_sender, response_receiver) = oneshot::channel::<Option<Vec<u8>>>();
        let cmd = StateUpdateCommand::GetInstanceResult { instance_id: instance_id.clone(), responder: response_sender };
        self.state_command_sender.send(cmd).await.expect("state_command_sender.send() returned Err");
        let response = response_receiver.await.expect("response_receiver.await returned Err");
        if let Some(_) = response {
             println!(">> REQH: A request with the same id already exists. Instance_id: {:?}", instance_id);
             return Err(Status::new(tonic::Code::AlreadyExists, format!("A similar request with request_id {instance_id} already exists")))
         }
        // Add this instance_id to state
        let cmd = StateUpdateCommand::AddInstanceResult { instance_id: instance_id.clone(), result: None};
        self.state_command_sender.send(cmd).await.expect("state_command_sender.send() returned Err");

        // Create demult_to_prot channel, so the message demultiplexor can forward messages to this instance
        let (demult_to_prot_sender, demult_to_prot_receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let cmd = DemultUpdateCommand::AddDemultToProtChannel { instance_id: instance_id.clone(), sender: demult_to_prot_sender };
        self.demult_command_sender.send(cmd).await.expect("demult_command_sender.send returned Err");
        
        // Start the new protocol instance as a new tokio task
        let mut prot = ThresholdCipherProtocol::<C>::new(
            sk.clone(),
            pk.clone(),
            ciphertext,
            demult_to_prot_receiver,
            self.prot_to_net_sender.clone(),
            self.result_sender.clone(),
            instance_id.clone()
        );
        // println!(">> REQH: Spawning new protocol instance with instance_id: {:?}", &instance_id);
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
        println!(">> REQH: Received a decryption request. Decrypting with key_id: {:?}", req.key_id);
        
        let req_scheme = requests::ThresholdCipher::from_i32(req.algorithm).unwrap();
        let req_domain = requests::DlGroup::from_i32(req.dl_group).unwrap();
        let key = self.key_chain.get_key(req_scheme, req_domain, None);
        if let Err(err) = key {
            return Err(Status::new(tonic::Code::InvalidArgument, "Key"))
        }
        let serialized_key = key.unwrap();

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
        // println!(">> NET: Received a decryption share. Instance_id: {:?}. Pushing to net_to_demult channel,", req.instance_id);
        let p2p_message = P2pMessage{
            instance_id: req.instance_id.clone(),
            message_data: req.decryption_share.clone()
        };
        self.net_to_demult_sender.send(p2p_message).await.expect("net_to_demult_sender.send returned Err");
        Ok(Response::new(requests::PushDecryptionShareResponse{}))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Please provide server ID.")
    }
    let my_id = u32::from_str(&args[1])?;
    let my_port = 50050 + my_id;
    let my_addr = format!("[::1]:{my_port}").parse()?;
    let my_keyfile = format!("conf/keys_{my_id}.json");
    
    let (prot_to_net_sender, prot_to_net_receiver) = tokio::sync::mpsc::channel::<P2pMessage>(32);
    let (net_to_demult_sender, mut net_to_demult_receiver) = tokio::sync::mpsc::channel::<P2pMessage>(32);
    let (state_command_sender, mut state_command_receiver) = tokio::sync::mpsc::channel::<StateUpdateCommand>(32);
    let state_command_sender2 = state_command_sender.clone();
    let (demult_command_sender, mut demult_command_receiver) = tokio::sync::mpsc::channel::<DemultUpdateCommand>(32);
    let (result_sender, mut result_receiver) = tokio::sync::mpsc::channel::<(InstanceId, Option<Vec<u8>>)>(32);
    let net_to_demult_sender2 = net_to_demult_sender.clone(); // todo: currenly not needed.

    // Read keys from file
    println!(">> REQH: Reading keys from keychain file: {}", my_keyfile);
    let key_chain: KeyChain = KeyChain::from_file(&my_keyfile); 
    
    // Spawn Network
    // Takes ownership of net_to_demult_sender and prot_to_net_receiver
    // println!(">> REQH: Initiating an RPC network instance.");
    // tokio::spawn(async move {
    //     let mut network_manager = RpcNetwork::new(my_id, net_to_demult_sender2, prot_to_net_receiver).await;
    //     loop {
    //         let message_from_protocol = network_manager.prot_to_net_receiver.recv().await;
    //         let (instance_id, message) = message_from_protocol.expect("prot_to_net_receiver.recv() returned None");
    //         network_manager.send_to_all(instance_id, message).await
    //     }
    //     // net_to_demult_sender supposed to be used here as well. Send received message through that channel
    // });
    
    println!(">> REQH: Initiating lib_P2P-based network instance.");
    tokio::spawn(async move {
        network::p2p::gossipsub::setup::init(prot_to_net_receiver,
                                              net_to_demult_sender,
                                         true,
                                                  my_id,
                                                4).await;
    });

    // Spawn State Manager
    // Takes ownership of state_command_receiver
    // println!(">> REQH: Initiating state manager.");
    tokio::spawn( async move {
        let mut instances_results_map: HashMap<String, Option<Vec<u8>> > = HashMap::new();
        loop {
            let state_update_command = state_command_receiver.recv().await;
            let command = state_update_command.expect("state_command_receiver.recv() returned None");
            match command {
                StateUpdateCommand::AddInstanceResult { instance_id, result} => {
                    instances_results_map.insert(instance_id, result); // this updates the value if key already existed
                },
                StateUpdateCommand::GetInstanceResult { instance_id, responder} => {
                    let result: Option<Vec<u8>> = if ! instances_results_map.contains_key(&instance_id) {
                        None
                    }
                    else {
                        instances_results_map.get(&instance_id).unwrap().clone()
                    };
                    responder.send(result).expect("The receiver end of the responder in StateUpdateCommand::GetInstanceResult dropped");
                },
            }
        }
    });

    // Spawn Demultiplexor
    // Takes ownership of demult_command_receiver and net_to_demult_receiver
    // println!(">> REQH: Initiating message demultiplexor.");
    tokio::spawn( async move {
        let mut channels_demult_to_prot: HashMap<InstanceId, tokio::sync::mpsc::Sender<Vec<u8>> >= HashMap::new();
        loop {
            tokio::select! {
                message_net_to_demult = net_to_demult_receiver.recv() => { // Received a message in message_net_to_demult. Forward it to the correct instance.
                    let P2pMessage{instance_id, message_data } = message_net_to_demult.expect("net_to_demult_receiver.recv() returned None");
                    let mut remove_channel = false;
                    if let Some(sender) = channels_demult_to_prot.get(&instance_id){  // Found a channel that connects us to instance_id.
                        if sender.is_closed(){
                            remove_channel = true;
                            // println!(">> DEMU: Did not forward message in net_to_prot. Protocol already finished. Instance_id: {:?}", &instance_id);
                        }
                        else {
                            sender.send(message_data).await.expect("sender.send() for net_to_demult channel returned Err"); // Forward the message through that channel
                            // println!(">> DEMU: Forwared message in net_to_prot. Instance_id: {:?}", &instance_id);
                        }
                    }
                    else { // Did not find a channel for the given instance_id
                        // todo: Handle this:
                        // instance_id might not exist because the instance has already finished -> That's ok.
                        // But instance_id might not exist because the decryption request has not arrived yet -> Backlog these messages.
                        // println!(">> DEMU: Did not forward message in net_to_prot. Protocol already finished. Instance_id: {:?}", &instance_id);
                    }
                    if remove_channel {
                        channels_demult_to_prot.remove(&instance_id);
                    }
                }
                demult_update_command = demult_command_receiver.recv() => { // Received a command. Execute it.
                    let command = demult_update_command.expect("demult_command_receiver.recv() returned None");
                    match command{
                        DemultUpdateCommand::AddDemultToProtChannel { instance_id, sender } => {
                            channels_demult_to_prot.insert(instance_id, sender);
                        },
                    }
                }
            }
        }
    });
    
    // Spawn Instance Monitor
    // Takes ownership of result_receiver and a clone of state_command_sender.
    tokio::spawn( async move {
        loop {
            let result = result_receiver.recv().await;
            let (instance_id, result) = result.expect("result_receiver.recv() returned None");
            // println!(">> INMO: Received result in result_channel. Instance_id: {:?}", instance_id);
            let cmd = StateUpdateCommand::AddInstanceResult { instance_id: instance_id.clone(), result };
            state_command_sender2.send(cmd).await.expect("state_command_sender2.send returned Err");
        }
    });
    
  // Start server
    println!(">> REQH: Request handler is starting. Listening on address: {my_addr}");
    let service = RequestHandler{
        key_chain,
        state_command_sender,
        demult_command_sender,
        prot_to_net_sender,
        result_sender,
        net_to_demult_sender: net_to_demult_sender2,
    };
    Server::builder()
        .add_service(ThresholdCryptoLibraryServer::new(service))
        .serve(my_addr)
        .await?;
    Ok(())
}