use std::process::exit;
use std::io::Write;
use std::path::PathBuf;
use std::{io, thread, time};

use clap::Parser;
use log::{error, info};
use rand::Rng;
use rand::distributions::Alphanumeric;
use hex::encode;
use env_logger::init;

use serde_json::Error;
use theta_schemes::interface::{Serializable, Signature};
use theta_schemes::keys::PublicKey;
use theta_schemes::scheme_types_impl::{SchemeDetails, GroupDetails};
use theta_schemes::util::printbinary;
use theta_schemes::interface::{Ciphertext, ThresholdCipher, ThresholdCipherParams};

use theta_proto::protocol_types::threshold_crypto_library_client::ThresholdCryptoLibraryClient;
use theta_proto::protocol_types::{DecryptRequest, SignRequest, CoinRequest, StatusRequest };
use theta_proto::scheme_types::{ThresholdScheme, Group};

use theta_orchestration::keychain::KeyChain;

use utils::client::cli::ClientCli;
use utils::client::types::ClientConfig;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    init();

    let version = env!("CARGO_PKG_VERSION");
    info!("Starting server, version: {}", version);

    let client_cli = ClientCli::parse();

    info!(
        "Loading configuration from file: {}",
        client_cli
            .config_file
            .to_str()
            .unwrap_or("Unable to print path, was not valid UTF-8"),
    );
    let config = match ClientConfig::from_file(&client_cli.config_file) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("{}", e);
            exit(1);
        }
    };

    let mut running = true;
    while running {
        _ = std::process::Command::new("clear").status().unwrap().success();

        println!("\n--------------");
        println!("Thetacrypt Demo");
        println!("---------------");
        println!("0 - Quit");
        println!("1 - Threshold Decryption");
        println!("2 - Threshold Signature");
        println!("3 - Threshold Coin");
        println!("---------------");
        print!("Your choice: ");

        io::stdout().flush().expect("error flushing stdout");

        let mut choice = String::new();
        
        io::stdin()
            .read_line(&mut choice)
            .expect("Failed to read line");
        let x: i32 = choice.trim().parse().expect("Input not an integer");

        match x {
            0 => {
                running = false; //return 
            },
            1 => {
                let result = threshold_decryption(config.clone()).await;
                if result.is_err() {
                    println!("Error while running decryption protocol: {}", result.unwrap_err().to_string());
                }

                println!("---------------\n\n");
            }, 
            2 => {
                let result = threshold_signature(config.clone()).await;
                if result.is_err() {
                    println!("Error while running signature protocol: {}", result.unwrap_err().to_string());
                }

                println!("---------------\n\n");
            },
            3 => {
                let result = threshold_coin(config.clone()).await;
                if result.is_err() {
                    println!("Error while running coin protocol: {}", result.unwrap_err().to_string());
                }

                println!("---------------\n\n");
            },
            _ => {
                println!("Invalid input");
            }
        }

        print!("Press [RETURN] to continue...");
        io::stdout().flush().expect("error flushing stdout");
        io::stdin().read_line(&mut choice)?;
    }
    
    Ok(())
}

async fn threshold_decryption(config: ClientConfig) -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file(&PathBuf::from("conf/keys_1.json"))?;
    let pk = key_chain_1
        .get_key_by_scheme_and_group(ThresholdScheme::Sg02, Group::Bls12381)?
        .sk
        .get_public_key();

    let mut connections = connect_to_all_local(config).await;

    print!(">> Enter message to encrypt: ");
    io::stdout().flush().expect("Error flushing stdout");

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let (request, ct) = create_decryption_request(&pk, input);
    printbinary(&request.ciphertext, Option::Some("Encrypted message:"));

    let mut i = 0;
    let mut instance_id= String::new();
    for conn in connections.iter_mut() {
        println!(">> Sending decryption request to server {i}.");
        let r = conn.decrypt(request.clone()).await.unwrap();
        instance_id = r.get_ref().instance_id.clone();
        i += 1;
    }

    let req = StatusRequest { instance_id };
    let mut status = connections[0].get_status(req.clone()).await?;

    while !status.get_ref().is_finished {
        thread::sleep(time::Duration::from_millis(100));
        status = connections[0].get_status(req.clone()).await?;
    }

    if status.get_ref().result.is_some() {
        let result = status.get_ref().result.as_ref().unwrap();
        if let Ok(s) = std::str::from_utf8(result) {
            println!(">> Received plaintext: {}", s);
        } else {
            printbinary(result, Option::Some(">> Received plaintext: "));
        }
    } else {
        println!("! Decryption computation failed");
    }

    Ok(())
}

async fn threshold_signature(config: ClientConfig) -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file(&PathBuf::from("conf/keys_1.json"))?;
    let pk = key_chain_1
        .get_key_by_scheme_and_group(ThresholdScheme::Frost, Group::Ed25519)?
        .sk
        .get_public_key();
    
    let mut connections = connect_to_all_local(config).await;

    print!(">> Enter message to sign: ");
    io::stdout().flush().expect("Error flushing stdout");

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let sign_request = create_signing_request(input.into_bytes());

    let mut i = 0;
    let mut instance_id= String::new();
    for conn in connections.iter_mut() {
        println!(">> Sending sign request to server {i}.");
        let r = conn.sign(sign_request.clone()).await.unwrap();
        instance_id = r.get_ref().instance_id.clone();
        i += 1;
    }

    let req = StatusRequest { instance_id };
    let mut status = connections[0].get_status(req.clone()).await?;

    while !status.get_ref().is_finished {
        thread::sleep(time::Duration::from_millis(100));
        status = connections[0].get_status(req.clone()).await?;
    }

    if status.get_ref().result.is_some() {
        let signature = status.get_ref().result.as_ref().unwrap();
        println!(">> Received signature: {}", encode(signature));
        
    } else {
        println!("! Signature computation failed");
    }

    Ok(())
}

async fn threshold_coin(config: ClientConfig) -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file(&PathBuf::from("conf/keys_1.json"))?;
    let pk = key_chain_1
        .get_key_by_scheme_and_group(ThresholdScheme::Cks05, Group::Bls12381)?
        .sk
        .get_public_key();
    let mut connections = connect_to_all_local(config).await;

    print!(">> Enter name of coin: ");
    io::stdout().flush().expect("Error flushing stdout");

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let coin_request = create_coin_flip_request(&pk, input);

    let mut i = 0;
    let mut instance_id= String::new();
    for conn in connections.iter_mut() {
        println!(">> Sending coin flip request to server {i}.");
        let r = conn.flip_coin(coin_request.clone()).await.unwrap();
        instance_id = r.get_ref().instance_id.clone();
        i += 1;
    }

    let req = StatusRequest { instance_id };
    let mut status = connections[0].get_status(req.clone()).await?;

    while !status.get_ref().is_finished {
        thread::sleep(time::Duration::from_millis(100));
        status = connections[0].get_status(req.clone()).await?;
    }

    if status.get_ref().result.is_some() {
        let result = status.get_ref().result.as_ref().unwrap();
        println!(">> Received coin flip result: {}", encode(result));
    } else {
        println!("! Coin computation failed");
    }

    Ok(())
}


fn create_decryption_request(pk: &PublicKey, msg_string: String) -> (DecryptRequest, Ciphertext) {
    let mut params = ThresholdCipherParams::new();
    let msg: Vec<u8> = msg_string.as_bytes().to_vec();

    let s: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let label = s.into_bytes(); // random label

    let ciphertext = ThresholdCipher::encrypt(&msg, &label, pk, &mut params).unwrap();

    let req = DecryptRequest {
        ciphertext: ciphertext.serialize().unwrap(),
        key_id: None,
    };
    (req, ciphertext)
}

fn create_coin_flip_request(pk: &PublicKey, name: String) -> CoinRequest {
    let req = CoinRequest {
        name:name.into_bytes(),
        key_id: None,
        scheme: ThresholdScheme::Cks05.get_id() as i32,
        group: Group::Bls12381.get_code() as i32
    };
    req
}

fn create_signing_request(message: Vec<u8>) -> SignRequest {
    let s: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let label = s.into_bytes(); // random label
    let req = SignRequest {
        message,
        label,
        key_id: None,
        scheme: ThresholdScheme::Frost.get_id() as i32,
        group: Group::Ed25519.get_code() as i32
    };

    req
}

async fn connect_to_all_local(config: ClientConfig) -> Vec<ThresholdCryptoLibraryClient<tonic::transport::Channel>> {
    let mut connections = Vec::new();
    for peer in config.peers.iter() {
        let ip = peer.ip.clone();
        let port = peer.rpc_port;
        let addr = format!("http://[{ip}]:{port}");
        connections.push(
            ThresholdCryptoLibraryClient::connect(addr.clone())
                .await
                .unwrap(),
        );
    }
    println!(">> Established connection to network.");
    connections
}
