// pub mod requests {
//     tonic::include_proto!("requests");
// }
use std::{error::Error, io::Read};
use cosmos_crypto::{keys::PublicKey, interface::{ThresholdCipherParams, Ciphertext, ThresholdCipher}};
use structopt::StructOpt;
use serde::{Deserialize, Deserializer, Serialize};
use reqwest;

#[derive(Debug, StructOpt)]
struct Opt {
    /// IP where the threshold crypto library is running.
    #[structopt(long, default_value = "127.0.0.1")]
    tendermint_node_ip: String,
    
    /// IP where the threshold crypto library is listening.
    #[structopt(long, default_value = "26657")]
    tendermint_node_rpc_port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt: Opt = Opt::from_args();
    
    let (key_id, public_key) = match query_tendermint_node(opt.tendermint_node_ip.clone(), 
                                                          opt.tendermint_node_rpc_port,
                                                       "get_encryption_keys").await {
        Ok(res) => {
            // the key_id is returned in res.result.key and the actual key bytes in res.result.value.
            match PublicKey::deserialize(&res.result.value) {
                Ok(pk) => {
                    (String::from_utf8(res.result.key)?, pk)
                },
                Err(err) => {
                    println!(">> The query either returned no key, or the key could not be deserialized.");
                    return Ok(());
                },
            }
        },
        Err(err) => {
            println!(">> Error when sending query. Err: {}", err);
            return Err(err);
        },
    };
  
    println!(">> Using public key with id {:?} to encrypt.", key_id);
    let encrypted_message = encrypt(&public_key, 
                                                   String::from("Hello world"),
                                                   String::from("Message 1"));

    match submit_tx_to_tendermint_node(opt.tendermint_node_ip, 
                                       opt.tendermint_node_rpc_port,
                                       encrypted_message.get_msg()).await {
        Ok(_) => {},
        Err(err) => println!(">> Error when submitting tx. Err: {}", err),
    }

    Ok(())
}

async fn query_tendermint_node(tendermint_node_ip: String,
                               tendermint_node_rpc_port: u16,
                               tx: &str) -> Result<RPCResult<QueryResult>, Box<dyn Error>> {
    println!(">> Start Query");
    let address = format!("http://{tendermint_node_ip}:{tendermint_node_rpc_port}");
    let req_url = address + "/abci_query?path=&data=" + tx;
    println!(">> Url query: {}", req_url);
    let response = reqwest::get(req_url).await?.json::<RPCResult<QueryResult>>().await?;
    println!(">> End Query");
    Ok(response)
}

async fn submit_tx_to_tendermint_node(tendermint_node_ip: String,
                                     tendermint_node_rpc_port: u16,
                                     tx: Vec<u8>) -> Result<RPCResult<BroadcastTxResult>, Box<dyn Error>> {
    let address = format!("{tendermint_node_ip}:{tendermint_node_rpc_port}");
    let req_url = address + "/broadcast_tx_commit?tx=" + std::str::from_utf8(&tx)?;
    let response = reqwest::get(req_url).await?.json::<RPCResult<BroadcastTxResult>>().await?;
    Ok(response)
}

fn encrypt(pk: &PublicKey, message: String, label: String) -> Ciphertext {
    let mut params = ThresholdCipherParams::new();
    let msg: Vec<u8> = message.as_bytes().to_vec();
    let ciphertext = ThresholdCipher::encrypt(&msg, label.as_bytes(), pk, &mut params).unwrap();
    ciphertext
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RPCResult<R> {
    jsonrpc: String,
    id: i8,
    pub result: R,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BroadcastTxResult {
    pub code: i8,
    pub data: String,
    pub log: String,
    pub codespace: String,
    pub hash: String,
}

fn parse_proof<'de, D>(d: D) -> Result<String, D::Error> where D: Deserializer<'de> {
    Deserialize::deserialize(d)
        .map(|x: Option<_>| {
            x.unwrap_or("null".to_string())
        })
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QueryResult {
    pub code: u32,
    pub log: String,
    pub info: String,
    pub index: i64,
    pub key: Vec<u8>, 
    pub value: Vec<u8>,
    #[serde(deserialize_with="parse_proof")]
    pub proof_ops: String, //Segmentation fault could be because of the null here in the json?
    pub height: i64,
    pub codespace: String,
}

