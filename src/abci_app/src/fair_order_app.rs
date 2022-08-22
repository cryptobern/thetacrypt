use std::{sync::mpsc::{Sender, Receiver, channel}, collections::HashMap, time::Duration};

use tendermint_proto::abci::{RequestDeliverTx, RequestQuery, ResponseDeliverTx, ResponseQuery};
use protocols::proto::protocol_types::{threshold_crypto_library_client::ThresholdCryptoLibraryClient, DecryptSyncRequest, GetPublicKeysForEncryptionRequest};

use tendermint_abci::{Application, Error};
use tonic::transport::Channel;

#[derive(Debug, Clone)]
pub struct FairOrderApp {
    command_sender: Sender<Command>,
}

impl FairOrderApp {
    pub async fn new(tcl_ip: String, tcl_port: u16) -> (Self, FairOrderDriver) { //todo: Pass through parameters, should change
        let (command_sender, command_receiver) = channel();
        let app = Self {command_sender};
        let driver = FairOrderDriver::new(tcl_ip, tcl_port, command_receiver).await;
        (app, driver)
    }
}

impl Application for FairOrderApp {
    
    // For simplicity we assume the only tx ever delivered is encrypted, and request.tx contains the ciphertext.
    // The abci_app is responsible for submiting this ciphertext to the threshold crypto library for decryption.
    // The 'channel_recv' endpoint used in this example is blocking, i.e., it will only return when the library
    // has decrypted the ciphertext. Hence, deliver_tx will obtain the decrypted transaction.
    // This sample code does not return the decrypted tx back to the client_app.
    fn deliver_tx(&self, request: RequestDeliverTx) -> ResponseDeliverTx {
        println!(">> Delivered an encrypted tx.");
        let ciphertext = request.tx;
        let (result_sender, result_receiver) = channel();
        let command = Command::DecryptTx { encrypted_tx: ciphertext, result_sender};
        channel_send(&self.command_sender, command).unwrap();
        let decrypted_tx = channel_recv(&result_receiver).unwrap();
        
        ResponseDeliverTx { 
            code: 0,
            data: Default::default(),
            log: "".to_string(),
            info: "".to_string(),
            gas_wanted: 0,
            gas_used: 0,
            events: Vec::new(),
            codespace: "".to_string(),
        }
    }

    // The client_app, in order to encrypt a tx, needs the public key that corresponds to the secret-key shares
    // held by the nodes of the threshold library app. Since this is only a query (the client_app does not submit
    // any data to the blockchain), this can be implemented in the 'abci_querry' function.
    // We assume the only query used by the client_app is for getting †he avaible public keys for encryption,
    // hence in this code we do not check the content of RequestQuery.
    // This simple implementation returns only the first key returned by the threshold library.
    fn query(&self, request: RequestQuery) -> ResponseQuery {
        println!(">> Delivered a query for avaible encryption keys.");
        let (result_sender, result_receiver) = channel();
        let command = Command::GetEncryptionKeys { result_sender};
        channel_send(&self.command_sender, command).unwrap();

        let (mut return_key_id, mut return_key_bytes) = (String::new(), Vec::new());
        let encryption_keys = channel_recv(&result_receiver).unwrap();
        match encryption_keys {
            Some(keys) => {
                for (key_id, key_bytes) in keys {
                    println!(">> Key: {:?}", key_bytes);
                    if return_key_id.is_empty(){
                        (return_key_id, return_key_bytes) = (key_id, key_bytes);
                    }
                }
            },
            None => {
                println!(">> No keys returned.");
            },
        }
        ResponseQuery{
            code: 0,
            log: "".to_string(),
            info: "".to_string(),
            index: 0,
            key: return_key_id.into_bytes(),
            value: return_key_bytes,
            proof_ops: None,
            height: 0,
            codespace: "".to_string(),
        }
    }
   
}


#[derive(Debug, Clone)]
enum Command {
    DecryptTx {
        encrypted_tx: Vec<u8>,
        result_sender: Sender<Option<Vec<u8>>>
    },
    GetEncryptionKeys {
        result_sender: Sender<Option<HashMap<String, Vec<u8>>>>
    }
}

pub struct FairOrderDriver {
    tcl_client: ThresholdCryptoLibraryClient<tonic::transport::Channel>,
    command_receiver: Receiver<Command>
}

impl FairOrderDriver {
    async fn new(tcl_ip: String, tcl_port: u16, command_receiver: Receiver<Command>) -> Self {
        let tcl_client: ThresholdCryptoLibraryClient<Channel>;
        loop {
            match ThresholdCryptoLibraryClient::connect(format!("http://[{tcl_ip}]:{tcl_port}")).await {
                Ok(client) => {
                    tcl_client = client;
                    break;
                },
                Err(err) => { 
                    println!(">> NET: Could not connect to threshold crypto library in {:?}:{:?}. Retrying in 2 sec. Error: {:?}", tcl_ip, tcl_port, err.to_string() );   
                    tokio::time::sleep(Duration::from_millis(2000)).await;
                }
            };
        }
            FairOrderDriver{tcl_client, command_receiver}
    }

    pub async fn run(mut self) -> Result<(), Error>{
        println!(">> Fair order driver starting.");
        loop {
            let cmd = self.command_receiver.recv().map_err(Error::channel_recv)?;
            match cmd {
                Command::DecryptTx { encrypted_tx, result_sender } => {
                    println!(">> Received DecryptTx command.");
                    let request = DecryptSyncRequest { ciphertext: encrypted_tx, key_id: None}; // todo: Remove this key_id
                    match self.tcl_client.decrypt_sync(request).await {
                        Ok(response) => { // The RPC call returned successfully.
                            match response.into_inner().plaintext {
                            // todo: Explain what this call returns: The instance_id used and the optional plaintext
                                Some(plaintext) => {
                                    // Decryption was succesfull, some plaintext was returned.
                                    channel_send(&result_sender, Some(plaintext))?
                                },
                                None => {
                                    // Decryption failed (e.g., because the ciphertext was malformed).
                                    channel_send(&result_sender, None)?
                                },
                            }
                        },
                        Err(err) => { // The RPC call failed, e.g., because the threshold library was not found, or the operation timed out.
                            // return Err(Error::io(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, format!("Call to threshold library failed. Error: {:?}", err.to_string()))));
                            println!(">> Call to threshold library failed. Error: {:?}", err.to_string());
                            channel_send(&result_sender, None)?
                        },
                    }
                },

                Command::GetEncryptionKeys { result_sender } => {
                    println!(">> Received GetEncryptionKeys command.");
                    let request = GetPublicKeysForEncryptionRequest{};
                    match self.tcl_client.get_public_keys_for_encryption(request).await {
                        Ok(response) => { // The RPC call returned successfully.
                        //todo: Explain what this call returns: KeyEntry, with id, group, scheme, key_data,... For this simple demo, we ignore group and scheme (don't eveb return to user)
                            let mut keys = HashMap::new();
                            for pk in response.into_inner().keys {
                                keys.insert(pk.id, pk.key);
                            }
                            channel_send(&result_sender, Some(keys))?
                        },
                        Err(err) => { // The RPC call failed, e.g., because the threshold library was not found, or the operation timed out.
                            println!(">> Call to threshold library failed. Error: {:?}", err.to_string());
                            channel_send(&result_sender, None)?
                        },
                    }
                },
            }
        }
    }
}


fn channel_send<T>(sender: &Sender<T>, value: T) -> Result<(), Error> {
    sender.send(value).map_err(Error::send)
}

fn channel_recv<T>(receiver: &Receiver<T>) -> Result<T, Error> {
    receiver.recv().map_err(Error::channel_recv)
}