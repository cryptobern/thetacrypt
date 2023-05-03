use std::{sync::mpsc::{Sender, Receiver, channel}, collections::HashMap, time::Duration};
use tendermint_proto::abci::{RequestDeliverTx, RequestQuery, ResponseDeliverTx, ResponseQuery, RequestCheckTx, ResponseCheckTx};
use thetacrypt_proto::protocol_types::{threshold_crypto_library_client::ThresholdCryptoLibraryClient, DecryptReponse, DecryptRequest, DecryptSyncRequest, GetPublicKeysForEncryptionRequest};
use tendermint_abci::{Application, Error};
use tonic::transport::Channel;
use base64;

#[derive(Debug, Clone)]
pub struct FairOrderApp {
    command_sender: Sender<Command>,
}

// FairOrderApp is a minimal ABCI app implementation, based on https://github.com/informalsystems/tendermint-rs/tree/main/abci.
// It implements a Causal broadcast layer on top of Tendermint, by employing threshold encryption.
// It delivers commands from Tendermint (deliver_tx(), query()) and handles them by calling, if required,
// the threshold-crypto related operations to the threshold crypto library. These calls are made over
impl FairOrderApp {
    pub async fn new(tcl_ip: String, tcl_port: u16) -> (Self, FairOrderDriver) { //todo: Pass through parameters, should change
        let (command_sender, command_receiver) = channel();
        let app = Self {command_sender};
        let driver = FairOrderDriver::new(tcl_ip, tcl_port, command_receiver).await;
        (app, driver)
    }
}

impl Application for FairOrderApp {
    
    // deliver_tx() checks if the delivered request.tx is a threshold-crypto related command and, if it is,
    // it handles it by calling the appropriate RPC endpoint of the treshold crypto library.
    fn deliver_tx(&self, request: RequestDeliverTx) -> ResponseDeliverTx {
        println!(">> Delivered a transaction.");
        let mut decrypt_result = None;

        // check if request.tx contains a threshold-crypto related command
        if let Some(thresh_command_parts) = FairOrderApp::extract_threshold_command_and_args(&request.tx){
            let command = thresh_command_parts[0];
            match command {
                "decrypt" => {
                    println!(">> Delivered a decrypt command.");
                    let arg = thresh_command_parts[1];
                    if let Ok(encrypted_payload) = base64::decode(arg){
                        decrypt_result = FairOrderApp::handle_decrypt_command(self.command_sender.clone(), encrypted_payload);   
                    }
                    else {
                        println!(">> Could not decode ciphertext from base64 format.");
                    }
                },
                _ => {
                    !unimplemented!()
                }
            }
        }

        // standard deliver_tx code...

        let mut response = ResponseDeliverTx { 
            code: 0,
            data: Vec::new(),
            log: "".to_string(),
            info: "".to_string(),
            gas_wanted: 0,
            gas_used: 0,
            events: Vec::new(),
            codespace: "".to_string(),
        };

        if let Some(decrypted_payload) = decrypt_result{
            response.data = decrypted_payload
        }
        
        response
    }
    
    // query() checks if the received request.data contains a threshold-crypto related command and, if it does,
    // it handles it by calling the appropriate RPC endpoint of the treshold crypto library.
    // The client_app, in order to encrypt a tx, needs the public key that corresponds to the secret-key shares
    // held by the nodes of the threshold library app. Since this is only a query (the client_app does not submit
    // any data to the blockchain), this can be implemented in the 'abci_querry' function.
    fn query(&self, request: RequestQuery) -> ResponseQuery {
        println!(">> Received a query.");
        let mut encryption_key: Option<(String, Vec<u8>)> = None;
        
        // check if request.data contains a threshold-crypto related command
        if let Some(thresh_command_parts) = FairOrderApp::extract_threshold_command_and_args(&request.data) {
            let command = thresh_command_parts[0];
            match command {
                "get_encryption_keys" => {
                    println!(">> Delivered a query for avaible encryption keys.");
                    encryption_key = FairOrderApp::handle_get_encryption_keys_command(self.command_sender.clone())
                },
                _ => {
                    !unimplemented!()
                }
            }
        }

        // standard deliver_tx code...
        
        let mut response = ResponseQuery{
            code: 0,
            log: "".to_string(),
            info: "".to_string(),
            index: 0,
            key: Vec::new(),
            value: Vec::new(),
            proof_ops: None,
            height: 0,
            codespace: "".to_string(),
        };

        if let Some((encryption_key_id, encryption_key_bytes)) = encryption_key {
            response.key = encryption_key_id.into_bytes();
            response.value = encryption_key_bytes
        }

        response
    }


    fn check_tx(&self, request: RequestCheckTx) -> ResponseCheckTx {
        println!(">> Check_tx called.");
        let resp = ResponseCheckTx {
            code: 0,
            data: Vec::new(),
            log: String::new(),
            info: String::new(),
            gas_wanted: 0,
            gas_used: 0,
            events: Vec::new(),
            codespace: String::new(),
            sender: String::new(),
            priority: 0,
            mempool_error: String::new(),
        };
        return resp;
    }
   
}

impl FairOrderApp {
    // We assume threshold-crypto related commands are in the form <command>:<arg1>:<arg2>...,
    // where <command> is a string and <arg_i> is an argument, encoded in a format that depends on the command.
    // e.g., for a threshold decryption command: decrypt:<arg>, where <arg> is the base64-encoded ciphertext.
    fn extract_threshold_command_and_args<'a>(request_tx: &'a Vec<u8>) -> Option<Vec<&'a str>> {
        let tx_str = match std::str::from_utf8(request_tx){
            Ok(str) => str,
            Err(_) => return None,
        };

        let command_parts: Vec<&str> = tx_str.split(':').collect();
        if command_parts.len() == 0 {
            return None; 
        }
        
        let command = command_parts[0];
        match command { //make the necessary correctness checks for each command
            "decrypt" => { // Syntax is decrypt:ctxt, so command_parts.len() should be 2
                if command_parts.len() >= 2 {
                    return Some(command_parts);
                }
            },
            "get_encryption_keys" => {
                return Some(command_parts);
            },
            _ => {
                return None
            }
        }
        return None
    }
 
    // Handles a "get_encryption_keys" command, by using the corresponding RPC endpoint of the threshold crypto libary.
    // If the library returns more than one public keys, this implementation for simplicity returns only the first
    // (in a real application it should return all available keys).
    fn handle_get_encryption_keys_command(command_sender: Sender<Command>) -> Option<(String, Vec<u8>)> {
        let (result_sender, result_receiver) = channel();
        let command = Command::GetEncryptionKeys { result_sender};
        channel_send(&command_sender, command).unwrap();
        
        match channel_recv(&result_receiver).unwrap() {
            Some(keys) => {
                let (mut first_key_id, mut first_key_bytes) = (String::new(), Vec::new());
                for (key_id, key_bytes) in keys {
                    println!(">> Using the first key returned by treshold cypto library. Key id: {:?}", key_id);
                    if first_key_id.is_empty() {
                        (first_key_id, first_key_bytes) =  (key_id, key_bytes);
                    }
                }
                return Some((first_key_id, first_key_bytes));
            },
            None => {
                println!(">> No keys returned by the threshold crypto library.");
                return None;
            },
        }

    }

    // Handles a "decrypt" command, by using the corresponding RPC endpoint of the threshold crypto libary.
    // This implementation uses the decrypt_sync RPC endpoint, which means it will return the decrypted payload.
    fn handle_decrypt_command(command_sender: Sender<Command>, ctxt: Vec<u8>) -> Option<Vec<u8>> {
        let (result_sender, result_receiver) = channel();
        let command = Command::DecryptTx { encrypted_tx: ctxt, result_sender};
        channel_send(&command_sender, command).unwrap();
        
        let protocol_result = channel_recv(&result_receiver).unwrap();
        protocol_result
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
                    println!(">> Initiating decryption of payload.");
                    let request = DecryptRequest { ciphertext: encrypted_tx, key_id: None}; // todo: Remove this key_id
                    //ROSE: move the decrypt in a thread
                    // tokio::spawn(async move || {

                    // });
                    match self.tcl_client.decrypt(request).await {
                        Ok(response) => {
                            match response.into_inner().instance_id{
                                id => {
                                    println!(">> Decryption protocol for instance id: {:?} started", id);
                                    channel_send(&result_sender, Some(id.as_bytes().to_vec()))?
                                }
                            }
                            
                        },
                        Err(e) => {
                            println!("Error in submitting the decrypt request");
                            channel_send(&result_sender, None)?
                        },
                    }

                    //DECRYPT-SYNC handling code
                    //  { 
                    //     Ok(response) => { // The RPC call returned successfully.
                    //         match response.into_inner().plaintext {
                    //         // todo: Explain what this call returns: The instance_id used and the optional plaintext
                    //             Some(plaintext) => {
                    //                 println!(">> Decryption protocol sucesfully terminated. Decrypted plaintext: {:?}", std::str::from_utf8(&plaintext));
                    //                 channel_send(&result_sender, Some(plaintext))?
                    //             },
                    //             None => {
                    //             println!(">> Decryption failed.");
                    //                 channel_send(&result_sender, None)?
                    //             },
                    //         }
                    //     },
                    //     Err(err) => { // The RPC call failed, e.g., because the threshold library was not found, or the operation timed out.
                    //         // return Err(Error::io(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, format!("Call to threshold library failed. Error: {:?}", err.to_string()))));
                    //         println!(">> Call to threshold library failed. Error: {:?}", err.to_string());
                    //         channel_send(&result_sender, None)?
                    //     },
                    // }
                },

                Command::GetEncryptionKeys { result_sender } => {
                    println!(">> Initiating a GetPublicKeysForEncryption request.");
                    let request = GetPublicKeysForEncryptionRequest{};
                    match self.tcl_client.get_public_keys_for_encryption(request).await {
                        Ok(response) => { // The RPC call returned successfully.
                        // The GetPublicKeysForEncryption endpoint returns a GetPublicKeysForEncryptionResponse,
                        // which contains a vector of PublicKeyEntry entries.
                        // Each entry contains with a key id, the group and scheme for which the key works, and the key itself.
                        // The groups and scheme can be used if the user app wants to encrypt using some specific scheme (e.g., for efficiency reasons).
                        // In this implementation, we ignore group and scheme and do not even return them to the user app.
                            println!(">> GetPublicKeysForEncryption request successfully terminated.");
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