use libp2p::{identity, PeerId};
use std::error::Error;

// use cosmos_crypto::{interface::ThresholdCipher, dl_schemes::ciphers::sg02::{Sg02ThresholdCipher}, rand::RngAlgorithm};
// use {cosmos_crypto::dl_schemes::{ciphers::sg02::{Sg02DecryptionShare}, dl_groups::{ bls12381::Bls12381}}};

// 1. create message
// 2. get addresses from tendermint network
// 3. broadcast message to all peers


// use reqwest;
// use std::error::Error;
// use serde::Deserialize;


// #[derive(Deserialize, Debug)]
// struct Peer {
//     node_id: i16,
//     url: String,
// }

// #[derive(Deserialize, Debug)]
// struct Response {
//     listening: bool,
//     listeners: Vec<String>,
//     n_peers: i32,
//     peers: Vec<Peer>,
// }

// use std::collections::HashMap;

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn Error>> {
//     // let mut map = HashMap::new();
//     // map.insert("lang", "rust");
//     // map.insert("body", "json");

//     let client = reqwest::Client::new();
//     // let res = client.post("http://127.0.0.1:26657/net_info")
//     //     .json(&map)
//     //     .send()
//     //     .await?;
//     // println!("{:#?}", res);

//     let response = client
//         .post("http://127.0.0.1:26657/net_info")
//         .header("ACCEPT", "application/json")
//         .header("CONTENT_TYPE", "application/json")
//         // .json(&map)
//         .send()
//         .await?
//         // .unwrap();
//         .text()
//         .await?;
//     println!("{:#?}", response);

//     Ok(())
// }


// use cosmos_crypto::{interface::ThresholdCipher, dl_schemes::ciphers::sg02::{Sg02ThresholdCipher}, rand::RngAlgorithm};
// cosmos_crypto::dl_schemes::{ciphers::sg02::{Sg02DecryptionShare}, dl_groups::{ bls12381::Bls12381}};
// cosmos_crypto::interface;

mod send;
mod receive;
use send::SendMessage;
use receive::DeliverMessage;
use cosmos_crypto::dl_schemes::ciphers::sg02::SG02_ThresholdCipher;

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let bc_msg = SendMessage { from: 123, msg: "hello world" };
    bc_msg.broadcast();
    let p2p_msg = SendMessage { from: 123, msg: "hello p2p world" };
    p2p_msg.p2p(789);

    let deliver_msg = DeliverMessage { from: 789, msg: "hello back" };
    deliver_msg.deliver();

    // generate secret shares for SG02 scheme over Bls12381 curve
    let sk = SG02_ThresholdCipher::generate_keys(K, N, Bls12381::new(), &mut rng);
    println!("Keys generated");

    // a public key is stored inside each secret share, so those can be used for encryption
    // let ciphertext = SG02_ThresholdCipher::encrypt(&msg, label, &sk[0].get_public_key(), &mut rng);

    Ok(())
}