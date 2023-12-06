use std::io::Write;
use std::process::exit;
use std::{io, thread, time};

use clap::Parser;
use env_logger::init;
use hex::encode;
use log::error;
use rand::distributions::Alphanumeric;
use rand::Rng;

use terminal_menu::{button, label, menu, mut_menu, run, TerminalMenuItem};
use theta_schemes::interface::Serializable;
use theta_schemes::interface::{Ciphertext, ThresholdCipher, ThresholdCipherParams};
use theta_schemes::keys::key_store::KeyStore;
use theta_schemes::keys::keys::PublicKey;
use theta_schemes::util::printbinary;

use theta_proto::protocol_types::threshold_crypto_library_client::ThresholdCryptoLibraryClient;
use theta_proto::protocol_types::{
    CoinRequest, DecryptRequest, KeyRequest, SignRequest, StatusRequest,
};

use utils::client::cli::ClientCli;
use utils::client::types::ClientConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init();

    let version = env!("CARGO_PKG_VERSION");
    println!("Starting server, version: {}", version);

    let client_cli = ClientCli::parse();
    let mut keystore = KeyStore::new();

    println!(
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

    println!("Connecting to network");
    let mut connections = connect_to_all_local(&config).await;
    let response = connections[0].get_public_keys(KeyRequest {}).await;
    if response.is_err() {
        println!("Error fetching public keys!");
        exit(1);
    }

    let response = response.unwrap();
    let keys = &response.get_ref().keys;
    if keystore.import_public_keys(keys).is_ok() {
        println!("Successfully imported public keys from server.");
    }

    // clear screen
    print!("\x1B[2J\x1B[1;1H");

    println!("\n--------------");
    println!("  ThetaCrypt");
    println!("--------------");

    let mut main_menu_items = Vec::new();
    if keystore.get_encryption_keys().len() > 0 {
        main_menu_items.push(button("Threshold Decryption"))
    }

    if keystore.get_signing_keys().len() > 0 {
        main_menu_items.push(button("Threshold Signature"))
    }

    if keystore.get_coin_keys().len() > 0 {
        main_menu_items.push(button("Threshold Coin"))
    }

    main_menu_items.push(button("Exit"));

    let main_menu = menu(main_menu_items);

    run(&main_menu);
    {
        let mm = mut_menu(&main_menu);

        if mm.selected_item_name() == "Exit" {
            exit(0);
        }

        let keys;

        match mm.selected_item_name() {
            "Threshold Decryption" => {
                keys = keystore.get_encryption_keys();
            }
            "Threshold Signature" => {
                keys = keystore.get_signing_keys();
            }
            "Threshold Coin" => {
                keys = keystore.get_coin_keys();
            }
            _ => unimplemented!("not implemented"),
        }

        let mut key_menu_items: Vec<TerminalMenuItem> =
            keys.iter().map(|x| button(x.to_string())).collect();
        key_menu_items.insert(0, label("Select Key:"));
        let key_menu = menu(key_menu_items);

        run(&key_menu);
        {
            let km = mut_menu(&key_menu);
            let key = keys
                .iter()
                .find(|k| km.selected_item_name().contains(&k.id));

            if key.is_none() {
                println!("Error importing key");
                exit(-1);
            }

            let key = &(key.unwrap().pk);

            match mm.selected_item_name() {
                "Threshold Decryption" => {
                    let _ = threshold_decryption(&config, key).await;
                }
                "Threshold Signature" => {
                    let _ = threshold_signature(&config, key).await;
                }
                "Threshold Coin" => {
                    let _ = threshold_coin(&config, key).await;
                }
                _ => unimplemented!("not implemented"),
            }
        }
    }

    Ok(())
}

async fn threshold_decryption(
    config: &ClientConfig,
    pk: &PublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut connections = connect_to_all_local(config).await;

    print!(">> Enter message to encrypt: ");
    io::stdout().flush().expect("Error flushing stdout");

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let (request, _ct) = create_decryption_request(pk, input);
    printbinary(&request.ciphertext, Option::Some("Encrypted message:"));

    let mut i = 0;
    let mut instance_id = String::new();
    for conn in connections.iter_mut() {
        print!("\n[Server {i}]: ");
        let result = conn.decrypt(request.clone()).await;
        if let Ok(r) = result {
            instance_id = r.get_ref().instance_id.clone();
            println!("OK");
        } else {
            println!("ERR: {}", result.unwrap_err().to_string());
        }

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

async fn threshold_signature(
    config: &ClientConfig,
    pk: &PublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut connections = connect_to_all_local(config).await;

    print!(">> Enter message to sign: ");
    io::stdout().flush().expect("Error flushing stdout");

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let sign_request = create_signing_request(pk, input.into_bytes());

    let mut i = 0;
    let mut instance_id = String::new();

    for conn in connections.iter_mut() {
        print!("[Server {i}]: ");
        let result = conn.sign(sign_request.clone()).await;
        if let Ok(r) = result {
            instance_id = r.get_ref().instance_id.clone();
            println!("OK");
        } else {
            println!("ERR: {}", result.unwrap_err().to_string());
        }

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

async fn threshold_coin(
    config: &ClientConfig,
    pk: &PublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut connections = connect_to_all_local(config).await;

    print!(">> Enter name of coin: ");
    io::stdout().flush().expect("Error flushing stdout");

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let coin_request = create_coin_flip_request(&pk, input);

    let mut i = 0;
    let mut instance_id = String::new();
    for conn in connections.iter_mut() {
        print!("[Server {i}]: ");
        let result = conn.flip_coin(coin_request.clone()).await;
        if let Ok(r) = result {
            instance_id = r.get_ref().instance_id.clone();
            println!("OK");
        } else {
            println!("ERR: {}", result.unwrap_err().message());
        }

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
        ciphertext: ciphertext.to_bytes().unwrap(),
        key_id: Some(pk.get_key_id().to_string()),
    };
    (req, ciphertext)
}

fn create_coin_flip_request(pk: &PublicKey, name: String) -> CoinRequest {
    let req = CoinRequest {
        name: name.into_bytes(),
        key_id: None,
        scheme: pk.get_scheme() as i32,
        group: *pk.get_group() as i32,
    };
    req
}

fn create_signing_request(pk: &PublicKey, message: Vec<u8>) -> SignRequest {
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
        scheme: pk.get_scheme() as i32,
        group: *pk.get_group() as i32,
    };

    req
}

async fn connect_to_all_local(
    config: &ClientConfig,
) -> Vec<ThresholdCryptoLibraryClient<tonic::transport::Channel>> {
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
    println!("Established connection to network.");
    connections
}
