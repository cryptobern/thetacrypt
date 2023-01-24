// pub mod requests {
//     tonic::include_proto!("requests");
// }
use std::{error::Error, io::Read};
use schemes::{keys::PublicKey, interface::{ThresholdCipherParams, Ciphertext, ThresholdCipher}};
use structopt::StructOpt;
use serde::{Deserialize, Deserializer, Serialize};
use reqwest;
use base64;
use serde_json;

#[derive(Debug, StructOpt)]
struct Opt {
    /// IP where the threshold crypto library is running.
    #[structopt(long, default_value = "127.0.0.1")]
    tendermint_node_ip: String,
    
    /// IP where the threshold crypto library is listening.
    #[structopt(long, default_value = "26657")]
    tendermint_node_rpc_port: u16,
}


// The client app will encrypt each transactions and submit it to the blockchain.
// The blockchain nodes hold shares of each public key -- they will first order incomming transactions
// and then cooperate to decrypt the ones that are encrypted.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt: Opt = Opt::from_args();

    // Retrieve the public keys for encryption from the blockchain.
    let encryption_pk = match query_tendermint(&opt, "get_encryption_keys").await {
        Ok(res) => {
            let key_id = String::from_utf8(res.result.response.key)
                                                      .map_err(|e| {format!("Could not parse key_id. Err: {e}") })?;
            let key =  PublicKey::deserialize(&res.result.response.value)
                                                      .map_err(|e| {format!("Could not deserialize key. Err: {:?}", e) })?;
            println!(">> Using key with id {key_id} for encryption.");
            key
            
        },
        Err(err) => {
            println!(">> Error when calling query().");
            return Err(err);
        },
    };
  
    // In a loop ask for user input (transaction), encrypt it, and submit it to the blockchain.
    // A threshold encryption algorithm needs, apart from the message, a label. This can be used to convey
    // additional info, to describe a decryption policy, or as a session id. This implementation detereminstically
    // assigns an increasing sequence number.
    // For each message, the client app encrypts it, then serializes it, then encodes it as base64, then escapes illegal
    // url characters, and finally submits it to a Tendermint node.
    // This demo implamentation uses broadcast_tx_commit, i.e., it will wait until the transation is ordered, delivered
    // by the app, and decrypted by the threshold library. The response to broadcast_tx_commit will contain the decrypted
    // message, which of course must be the same as the message submitted by the client app.
    let mut i = 0;
    loop {
        let msg: String = text_io::read!("{}\n");
        i += 1;
        if msg.is_empty(){ break };

        let msg_encr = encrypt(&encryption_pk, msg, format!("Label {i}"));
        let msg_ser = msg_encr.serialize().map_err(|e| {format!("Could not serialize msg. Err: {}", e)})?;
        let msg_enc: &str = &base64::encode(&msg_ser);
        let msg_esc = urlencoding::encode(msg_enc).to_owned();

        match submit_decrypt_tx_to_tendermint(&opt, &msg_esc).await {
            Ok(res) => {
                println!(">> Call to Tendermint succeeded.");
                println!(">> RESPONSE: {:?}", res.result);
                match res.result.deliver_tx.data {
                    Some(msg) => {
                        let msg_dec =  base64::decode(&msg)?;
                        let msg_str = std::str::from_utf8(&msg_dec)?;
                        println!(">> Returned data: {:?}.", msg_str);
                    },
                    None => {
                        println!(">>The decryption of the message failed.");
                    },
                }
            },
            Err(err) => println!(">> Error when submitting tx. Err: {}", err),
        }
    }

    Ok(())
}

async fn query_tendermint(opt: &Opt, query: &str) -> Result< RPCResult<RPCResponse<QueryResult>>, Box<dyn Error> > {  
    let address = format!("http://{}:{}", opt.tendermint_node_ip, opt.tendermint_node_rpc_port);
    let req_url = address + "/abci_query?data=\"" + query + "\""; // ?path=&data=" + tx;
    //let req_url = address + "/abci_query"; 
    
    //De-comment for testing with POSTMAN mock server 
    // let address = format!("https://25492e3f-d30c-499b-8b1a-75efcd8870eb.mock.pstmn.io");
    // let req_url = address + "/abci_query?path=&data=" + tx + "&PMAK-630e38a93466ec3eeebad3dc-40895e607418ddcdbe2fa003b59878b367";

    println!(">> Calling query() on Tendermint RPC. Url: {}", req_url);
    let response = reqwest::get(req_url).await?.json::<RPCResult<RPCResponse<QueryResult>>>().await?;
    Ok(response)
}

async fn submit_decrypt_tx_to_tendermint(opt: &Opt, tx: &str) -> Result<RPCResult<BroadcastTxCommitResult>, Box<dyn Error>> {
    let address = format!("http://{}:{}", opt.tendermint_node_ip, opt.tendermint_node_rpc_port);
    let req_url = address + "/broadcast_tx_commit?tx=\"decrypt:" + tx + "\"";

    println!(">> Calling broadcast_tx_commit() on Tendermint RPC. Url: {}", req_url);
    let response_body = reqwest::get(req_url).await?.text().await?;
    let response: RPCResult<BroadcastTxCommitResult> = serde_json::from_str(&response_body)?;
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
pub struct RPCResponse<R>{
    pub response: R,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BroadcastTxResult {
    pub code: i8,
    pub data: String,
    pub log: String,
    pub codespace: String,
    pub hash: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BroadcastTxCommitResult {
    pub check_tx: CheckTx,
    pub deliver_tx: DeliverTx,
    pub hash: String,
    pub height: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CheckTx {
    pub code: u32,
    pub data: Option<String>,
    pub log: String,
    pub info: String,
    pub gas_wanted: String,
    pub gas_used: String,
    pub events: Vec<String>,
    pub codespace: String,
    pub sender: String,
    pub priority: String,
    pub mempoolError: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeliverTx {
    pub code: u32,
    pub data: Option<String>,
    pub log: String,
    pub info: String,
    pub gas_wanted: String,
    pub gas_used: String,
    pub events: Vec<String>,
    pub codespace: String,
} 

fn parse_key<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = Option::<String>::deserialize(d)?.unwrap_or_default();
        base64::decode(&string).map_err(serde::de::Error::custom)
    }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QueryResult {
    pub code: u32,
    pub log: String,
    pub info: String,
    pub index: String,
    #[serde(deserialize_with = "parse_key")]
    pub key: Vec<u8>,
    #[serde(deserialize_with = "parse_key")]
    pub value: Vec<u8>,
    #[serde(alias="proofOps")]
    pub proof_ops: Option<String>, 
    pub height: String,
    pub codespace: String,
}

