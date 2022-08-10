use std::{sync::mpsc::{Sender, Receiver, channel}, collections::HashMap};

use tendermint_proto::abci::{
    Event, EventAttribute, RequestCheckTx, RequestDeliverTx, RequestInfo, RequestQuery,
    ResponseCheckTx, ResponseCommit, ResponseDeliverTx, ResponseInfo, ResponseQuery,
    RequestEcho, ResponseEcho, RequestInitChain, ResponseInitChain, RequestBeginBlock,
    ResponseBeginBlock,
};
use protocols::proto::protocol_types::{threshold_crypto_library_client::ThresholdCryptoLibraryClient, DecryptSyncRequest, GetPublicKeysForEncryptionRequest};

use tendermint_abci::{Application, Error};


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
        let tcl_client = match ThresholdCryptoLibraryClient::connect(format!("http://[{tcl_ip}]:{tcl_port}")).await {
            Ok(client) => {client},
            Err(err) => { panic!("Could not connect to thershold crypto library. Error: {:?}", err.to_string()) },
        };
        FairOrderDriver{tcl_client, command_receiver}
    }

    pub async fn run(mut self) -> Result<(), Error>{
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
    // fn echo(&self, request: RequestEcho) -> ResponseEcho {
        
    //     ResponseEcho {
    //         message: request.message,
    //     }
    // }

    // fn info(&self, _request: RequestInfo) -> ResponseInfo {
    //     Default::default()
    // }

    // fn init_chain(&self, _request: RequestInitChain) -> ResponseInitChain {
    //     Default::default()
    // }

    fn query(&self, _request: RequestQuery) -> ResponseQuery {
        Default::default()
    }

    fn check_tx(&self, _request: RequestCheckTx) -> ResponseCheckTx {
        Default::default()
    }

    // fn begin_block(&self, _request: RequestBeginBlock) -> ResponseBeginBlock {
    //     Default::default()
    // }

    fn deliver_tx(&self, request: RequestDeliverTx) -> ResponseDeliverTx {
        let tx = std::str::from_utf8(&request.tx).unwrap();
        let (command, operand) = tx.split_once('=').unwrap();
        match command{
            "order_encrypted" => { 
                let (result_sender, result_receiver) = channel();
                let command = Command::DecryptTx { encrypted_tx: operand.as_bytes().to_vec(), result_sender};
                channel_send(&self.command_sender, command).unwrap();
                let decrypted_tx = channel_recv(&result_receiver).unwrap();
                // todo: Return value?
            },
            "get_encryption_keys" => {
                let (result_sender, result_receiver) = channel();
                let command = Command::GetEncryptionKeys { result_sender};
                channel_send(&self.command_sender, command).unwrap();
                let encryption_keys = channel_recv(&result_receiver).unwrap();
                // todo: Return value?
            },
            &_ => {}
        };
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

    // fn end_block(&self, _request: RequestEndBlock) -> ResponseEndBlock {
    //     Default::default()
    // }

    // fn flush(&self) -> ResponseFlush {
    //     ResponseFlush {}
    // }

    fn commit(&self) -> ResponseCommit {
        Default::default()
    }

    fn echo(&self, request: RequestEcho) -> ResponseEcho {
        ResponseEcho {
            message: request.message,
        }
    }

    fn info(&self, _request: RequestInfo) -> ResponseInfo {
        Default::default()
    }

    fn init_chain(&self, _request: RequestInitChain) -> ResponseInitChain {
        Default::default()
    }

    fn begin_block(&self, _request: RequestBeginBlock) -> ResponseBeginBlock {
        Default::default()
    }

    fn end_block(&self, _request: tendermint_proto::abci::RequestEndBlock) -> tendermint_proto::abci::ResponseEndBlock {
        Default::default()
    }

    fn flush(&self) -> tendermint_proto::abci::ResponseFlush {
        tendermint_proto::abci::ResponseFlush {}
    }

    fn set_option(&self, _request: tendermint_proto::abci::RequestSetOption) -> tendermint_proto::abci::ResponseSetOption {
        Default::default()
    }

    fn list_snapshots(&self) -> tendermint_proto::abci::ResponseListSnapshots {
        Default::default()
    }

    fn offer_snapshot(&self, _request: tendermint_proto::abci::RequestOfferSnapshot) -> tendermint_proto::abci::ResponseOfferSnapshot {
        Default::default()
    }

    fn load_snapshot_chunk(&self, _request: tendermint_proto::abci::RequestLoadSnapshotChunk) -> tendermint_proto::abci::ResponseLoadSnapshotChunk {
        Default::default()
    }

    fn apply_snapshot_chunk(
        &self,
        _request: tendermint_proto::abci::RequestApplySnapshotChunk,
    ) -> tendermint_proto::abci::ResponseApplySnapshotChunk {
        Default::default()
    }

    // fn set_option(&self, _request: RequestSetOption) -> ResponseSetOption {
    //     Default::default()
    // }

    // fn list_snapshots(&self) -> ResponseListSnapshots {
    //     Default::default()
    // }

    // fn offer_snapshot(&self, _request: RequestOfferSnapshot) -> ResponseOfferSnapshot {
    //     Default::default()
    // }

    // fn load_snapshot_chunk(&self, _request: RequestLoadSnapshotChunk) -> ResponseLoadSnapshotChunk {
    //     Default::default()
    // }

    // fn apply_snapshot_chunk(
    //     &self,
    //     _request: RequestApplySnapshotChunk,
    // ) -> ResponseApplySnapshotChunk {
    //     Default::default()
    // }
}

fn channel_send<T>(sender: &Sender<T>, value: T) -> Result<(), Error> {
    sender.send(value).map_err(Error::send)
}

fn channel_recv<T>(receiver: &Receiver<T>) -> Result<T, Error> {
    receiver.recv().map_err(Error::channel_recv)
}