use std::{sync::mpsc::{Sender, Receiver, channel}, collections::HashMap, time::Duration};

use tendermint_proto::abci::{RequestDeliverTx, RequestQuery, ResponseDeliverTx, ResponseQuery, RequestCheckTx, ResponseCheckTx};
use protocols::proto::protocol_types::{threshold_crypto_library_client::ThresholdCryptoLibraryClient, DecryptSyncRequest, GetPublicKeysForEncryptionRequest};

use tendermint_abci::{Application, Error};
use tonic::transport::Channel;

use base64;

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
    
    // deliver_tx checks if the deliver request.tx is a threshold-crypto related command.
    // In this example we only handle decrypt comamnds:
    // The abci_app is responsible for submiting the ciphertext to the threshold crypto library for decryption.
    // The 'channel_recv' endpoint used in this example is blocking, i.e., it will only return when the library
    // has decrypted the ciphertext. Hence, deliver_tx will obtain the decrypted transaction.
    fn deliver_tx(&self, request: RequestDeliverTx) -> ResponseDeliverTx {
        let mut default_resp = ResponseDeliverTx { 
            code: 0,
            data: Vec::new(),
            log: "".to_string(),
            info: "".to_string(),
            gas_wanted: 0,
            gas_used: 0,
            events: Vec::new(),
            codespace: "".to_string(),
        };

        // Try parsing request.tx as a UTF8 string.
        let tx_str = match String::from_utf8(request.tx.clone()){
            Ok(tx_str) => tx_str,
            Err(err) => {
                println!(">> Could not parse request.tx as a UTF8 string. Err:{:?}, Tx:{:?}", err, &request.tx);
                return default_resp
            },
        };
        
        // Check if request.tx is a threshold-crypto related command.
        // We assume such commands are in the form <command>:<arg1>:<arg2>...,
        // where <command> is a string and <arg> is a base64 encoded argument,
        // e.g., decrypt:<ciphertext>.
        match tx_str.split_once(':'){
            Some((command, argument)) => {
                match command {
                    "decrypt" => {
                        println!(">> Received a decrypt command. {:?}", request.tx);
                        return decrypt_ctxt(self.command_sender.clone(), argument)
                    },
                    _ => {
                        println!(">> The received request.tx does not contain a known threshold crypto command.");
                        return default_resp        
                    }
                }
            },
            None => {
                println!(">> The received request.tx does not contain a threshold crypto command.");
                return default_resp
            },
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


    fn check_tx(&self, request: RequestCheckTx) -> ResponseCheckTx {
        println!(">> CheckTx. Tx:{:?}", &request.tx);
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

fn decrypt_ctxt(command_sender: Sender<Command>, ctxt: &str) -> ResponseDeliverTx {
    let mut default_resp = ResponseDeliverTx { 
        code: 0,
        data: Vec::new(),
        log: "".to_string(),
        info: "".to_string(),
        gas_wanted: 0,
        gas_used: 0,
        events: Vec::new(),
        codespace: "".to_string(),
    };
    println!(">> Encoded: {}", ctxt);
    match base64::decode(ctxt){
        Ok(ciphertext) => {
            let (result_sender, result_receiver) = channel();
            let command = Command::DecryptTx { encrypted_tx: ciphertext, result_sender};
            channel_send(&command_sender, command).unwrap();
            let decrypted_tx = channel_recv(&result_receiver).unwrap();
            if let Some(plaintext) = decrypted_tx {  
                default_resp.data = plaintext;
                return default_resp;
            }
        },
        Err(err) => {
            println!(">> Could not decode ciphertext from base64. Err: {:?}", err);
            return default_resp;
        },
             
    }
    return default_resp
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