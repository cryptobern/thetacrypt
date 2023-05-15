use std::io::Write;
use std::path::PathBuf;
use std::{io, vec, thread, time};

use protocols::keychain::KeyChain;
use rand::Rng;
use rand::distributions::Alphanumeric;
use schemes::interface::Serializable;
use schemes::keys::PublicKey;
use schemes::util::printbinary;
use schemes::{
    group::Group,
    interface::{Ciphertext, ThresholdCipher, ThresholdCipherParams, ThresholdScheme},
};

use thetacrypt_proto::protocol_types::threshold_crypto_library_client::ThresholdCryptoLibraryClient;
use thetacrypt_proto::protocol_types::{DecryptRequest, SignRequest, GetSignatureResultRequest, CoinRequest, GetDecryptResultRequest, GetCoinResultRequest};

// Send a single decrypt() request.
// To run it, start *four* server instances with peer ids 1-4, listening on localhost ports 51000-51003.
// They should be able to connect to each other.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
                running = false;
            },
            1 => {
                let result = threshold_decryption().await;
                if result.is_err() {
                    println!("Error while running signature protocol: {}", result.unwrap_err().to_string());
                }

                println!("---------------\n\n");
            }, 
            2 => {
                let result = threshold_signature().await;
                if result.is_err() {
                    println!("Error while running signature protocol: {}", result.unwrap_err().to_string());
                }

                println!("---------------\n\n");
            },
            3 => {
                let result = threshold_coin().await;
                if result.is_err() {
                    println!("Error while running signature protocol: {}", result.unwrap_err().to_string());
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

async fn threshold_decryption() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file(&PathBuf::from("conf/keys_1.json"))?;
    let pk = key_chain_1
        .get_key_by_scheme_and_group(ThresholdScheme::Sg02, Group::Bls12381)?
        .sk
        .get_public_key();

    let mut connections = connect_to_all_local().await;

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

    let req = GetDecryptResultRequest { instance_id };
    let mut result = connections[0].get_decrypt_result(req.clone()).await?;

    while !result.get_ref().is_finished {
        thread::sleep(time::Duration::from_millis(100));
        result = connections[0].get_decrypt_result(req.clone()).await?;
    }

    if result.get_ref().plaintext.is_some() {
        if let Ok(s) = std::str::from_utf8(&result.get_ref().plaintext()) {
            println!(">> Received plaintext: {}", s);
        } else {
            printbinary(result.get_ref().plaintext(), Option::Some(">> Received plaintext: "));
        }
    } else {
        println!("! Decryption computation failed");
    }

    Ok(())
}

async fn threshold_signature() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file(&PathBuf::from("conf/keys_1.json"))?;
    let pk = key_chain_1
        .get_key_by_scheme_and_group(ThresholdScheme::Frost, Group::Bls12381)?
        .sk
        .get_public_key();
    
    let mut connections = connect_to_all_local().await;

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

    let req = GetSignatureResultRequest { instance_id };
    let mut result = connections[0].get_signature_result(req.clone()).await?;

    while !result.get_ref().is_finished {
        thread::sleep(time::Duration::from_millis(100));
        result = connections[0].get_signature_result(req.clone()).await?;
    }

    if result.get_ref().signature.is_some() {
        printbinary(result.get_ref().signature(), Option::Some(">> Received signature: "));
    } else {
        println!("! Signature computation failed");
    }

    Ok(())
}

async fn threshold_coin() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file(&PathBuf::from("conf/keys_1.json"))?;
    let pk = key_chain_1
        .get_key_by_scheme_and_group(ThresholdScheme::Cks05, Group::Bls12381)?
        .sk
        .get_public_key();
    let mut connections = connect_to_all_local().await;

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

    let req = GetCoinResultRequest { instance_id };
    let mut result = connections[0].get_coin_result(req.clone()).await?;

    while !result.get_ref().is_finished {
        thread::sleep(time::Duration::from_millis(100));
        result = connections[0].get_coin_result(req.clone()).await?;
    }

    if result.get_ref().coin.is_some() {
        println!(">> Received coin flip result: {}", result.get_ref().coin.unwrap());
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
        scheme: ThresholdScheme::Bls04.get_id() as i32,
        group: Group::Bls12381.get_code() as i32
    };

    req
}

async fn connect_to_all_local() -> Vec<ThresholdCryptoLibraryClient<tonic::transport::Channel>> {
    let peers = vec![
        (0, String::from("127.0.0.1"), 51000),
        (1, String::from("127.0.0.1"), 51001),
        (2, String::from("127.0.0.1"), 51002),
        (3, String::from("127.0.0.1"), 51003),
    ];
    let mut connections = Vec::new();
    for peer in peers.iter() {
        let (_, ip, port) = peer.clone();
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
