use std::{
    collections::{HashMap, HashSet},
    io,
    path::PathBuf,
    thread, time, vec,
};
use tokio::task::JoinHandle;
use tonic::{Code, Response, Status};

use mcore::hash256::HASH256;
use theta_orchestration::keychain::KeyChain;
use theta_schemes::{keys::PublicKey, interface::Serializable};
use theta_schemes::{
    interface::{Ciphertext, ThresholdCipher, ThresholdCipherParams},
};

use theta_proto::{protocol_types::threshold_crypto_library_client::ThresholdCryptoLibraryClient, scheme_types::{ThresholdScheme, Group}};
use theta_proto::protocol_types::DecryptRequest;
use theta_proto::protocol_types::GetDecryptResultRequest;
use theta_proto::protocol_types::{GetPublicKeysForEncryptionRequest, PublicKeyEntry};

// test_local_servers() tests basic communication for nodes that run on localhost.
// It is meant to test the basic network logic RpcRequestHandler, MessageDispatcher, etc.
// To run it, start *four* server instances with peer ids 1-4, listening on localhost ports 51000-51003.
// They should be able to connect to each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_local_servers() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file(&PathBuf::from("../../conf/keys_1.json"))?;
    let pk = key_chain_1
        .get_key_by_scheme_and_group(ThresholdScheme::Sg02, Group::Bls12381)?
        .sk
        .get_public_key();
    let (request, _) = create_decryption_request(1, &pk);
    let (request2, _) = create_decryption_request(2, &pk);

    let mut connections = connect_to_all_local().await;

    // Ask for decrypt result before sending decrypt request
    let mut i = 0;
    let get_result_request = GetDecryptResultRequest {
        instance_id: String::from("Some instance that does not exist yet."),
    };
    for conn in connections.iter_mut() {
        println!(">> Sending get_decrypt_result request to server {i}.");
        let response = conn
            .get_decrypt_result(get_result_request.clone())
            .await
            .expect("This should not return Err");
        let get_result_response = response.into_inner();
        assert!(get_result_response.is_started == false);
        assert!(get_result_response.is_finished == false);
        assert!(get_result_response.plaintext == None);
        i += 1;
    }

    // Send decrypt request 1
    let mut i = 0;
    let mut instance_id = String::new();
    for conn in connections.iter_mut() {
        println!(">> Sending decryption request 1 to server {i}.");
        let response = conn
            .decrypt(request.clone())
            .await
            .expect("This should not return Err");
        instance_id = response.get_ref().instance_id.clone();

        // Immediately ask for decrypt result. The instance cannot have finished at this point
        if i == 0 {
            let get_result_request = GetDecryptResultRequest {
                instance_id: instance_id.clone(),
            };
            println!(">> Sending get_decrypt_result request to server {i}.");
            let response = conn
                .get_decrypt_result(get_result_request.clone())
                .await
                .expect("This should not return Err");
            let get_result_response = response.into_inner();
            assert!(get_result_response.is_started == true);
            assert!(get_result_response.is_finished == false);
            assert!(get_result_response.plaintext == None);
        }

        i += 1;
    }

    // Delay
    thread::sleep(time::Duration::from_millis(1000));

    // Ask for decrypt result. Instance should have finished by now.
    let mut i = 0;
    let get_result_request = GetDecryptResultRequest {
        instance_id: instance_id.clone(),
    };
    for conn in connections.iter_mut() {
        println!(">> Sending get_decrypt_result request to server {i}.");
        let response = conn
            .get_decrypt_result(get_result_request.clone())
            .await
            .expect("This should not return Err");
        let get_result_response = response.into_inner();
        assert!(get_result_response.is_started == true);
        assert!(get_result_response.is_finished == true);
        match get_result_response.plaintext {
            Some(plaintext) => {
                println!(
                    ">> Decrypted plaintext: {:?}.",
                    String::from_utf8(plaintext).unwrap()
                );
            }
            None => panic!("This should return Some(plaintext)."),
        }
        i += 1;
    }

    // Send decrypt request 2
    let mut i = 0;
    for conn in connections.iter_mut() {
        println!(">> Sending decryption request 2 to server {i}.");
        let _ = conn.decrypt(request2.clone()).await.unwrap();
        i += 1;
    }

    // Send DUPLICATE requests
    let mut i = 0;
    for conn in connections.iter_mut() {
        println!(">> Sending DUPLICATE decryption request 1 to server {i}.");
        let response = conn
            .decrypt(request.clone())
            .await
            .expect_err("This should return Err");
        assert!(response.code() == Code::AlreadyExists);
        // let response2 = conn.decrypt(request2.clone()).await.unwrap();
        i += 1;
    }

    Ok(())
}

// test_local_servers_backlog() tests the backlog functionality on nodes that run on localhost.
// To run it, start *four* server instances with peer ids 1-4, listening on localhost ports 51000-51003. They should be able to connect to each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_local_servers_backlog() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file(&PathBuf::from("../../conf/keys_1.json"))?;
    let pk = key_chain_1
        .get_key_by_scheme_and_group(ThresholdScheme::Sg02, Group::Bls12381)?
        .sk
        .get_public_key();
    let (request, _) = create_decryption_request(10, &pk);
    let (request2, _) = create_decryption_request(11, &pk);

    let mut connections = connect_to_all_local().await;
    let mut instance_id1 = String::new();

    let mut i = 0;
    for conn in connections.iter_mut() {
        // Send two decryption request to one server and wait before you send it to the next,
        println!(">> Sending decryption request 1 to server {i}.");
        let response1 = conn.decrypt(request.clone()).await.unwrap();
        instance_id1 = response1.get_ref().instance_id.clone();
        println!(">> Sending decryption request 2 to server {i}.");
        let _ = conn.decrypt(request2.clone()).await.unwrap();
        thread::sleep(time::Duration::from_millis(2000));
        i += 1;
    }

    // Ask for decrypt result. Instance should have finished by now.
    let mut i = 0;
    let get_result_request
     = GetDecryptResultRequest {
        instance_id: instance_id1,
    };
    for conn in connections.iter_mut() {
        println!(">> Sending get_decrypt_result request to server {i}.");
        let response = conn
            .get_decrypt_result(get_result_request.clone())
            .await
            .expect("This should not return Err");
        let get_result_response = response.into_inner();
        assert!(get_result_response.is_started == true);
        assert!(get_result_response.is_finished == true);
        match get_result_response.plaintext {
            Some(plaintext) => {
                println!(
                    ">> Decrypted plaintext: {:?}.",
                    String::from_utf8(plaintext).unwrap()
                );
            }
            None => panic!("This should return Some(plaintext)."),
        }
        i += 1;
    }
    Ok(())
}

// test_tendermint_servers() tests basic library functionality, such as the `decrypt` endpoint,
// for nodes that run on docker containers.
// To run it, start *four* threshold-library server instances with peer ids 1--4,
// istening on ips 192.167.10.2--4 and port 51000.
async fn test_servers_dockerized() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain: KeyChain = KeyChain::from_file(&PathBuf::from("../../conf/keys_1.json"))?;
    let pk = key_chain
        .get_key_by_scheme_and_group(ThresholdScheme::Sg02, Group::Bls12381)?
        .sk
        .get_public_key();
    let (request, ciphertext) = create_decryption_request(20, &pk);
    let (request2, ciphertext2) = create_decryption_request(21, &pk);

    let mut connections = connect_to_all_dockerized().await;

    let mut i = 0;
    for conn in connections.iter_mut() {
        println!(">> Sending decryption request 1 to server {i}.");
        let response = conn
            .decrypt(request.clone())
            .await
            .expect("This should not return Err");
        i += 1;
    }

    // Send DUPLICATE requests
    let mut i = 0;
    for conn in connections.iter_mut() {
        println!(">> Sending DUPLICATE decryption request 1 to server {i}.");
        let response = conn
            .decrypt(request.clone())
            .await
            .expect_err("This should return Err");
        assert!(response.code() == Code::AlreadyExists);
        // let response2 = conn.decrypt(request2.clone()).await.unwrap();
        i += 1;
    }

    let mut i = 0;
    for conn in connections.iter_mut() {
        println!(">> Sending decryption request 2 to server {i}.");
        let response = conn.decrypt(request2.clone()).await.unwrap();
        // let response2 = conn.decrypt(request2.clone()).await.unwrap();
        // println!("RESPONSE={:?}", response);
        i += 1;
    }

    Ok(())
}

async fn abci_app_emulation() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to all nodes. In a real ABCI app only connecting to the local node would be required.
    let mut connections = connect_to_all_local().await;

    let quorum = 3; // todo: This number should also come from an Rpc request
    let mut advertised_public_keys: HashMap<[u8; 32], PublicKeyEntry> = HashMap::new();
    let mut advertised_public_keys_count: HashMap<[u8; 32], u32> = HashMap::new();

    // Ask all the nodes for their available public keys. We say each node "advertises" some public keys.
    let req = GetPublicKeysForEncryptionRequest {};
    let mut responses = Vec::new();
    let mut i = 0;
    for conn in connections.iter_mut() {
        println!(">> Sending a get-keys request to node {i}.");
        match conn.get_public_keys_for_encryption(req.clone()).await {
            Ok(response) => {
                let response_keys = response.into_inner().keys;
                println!(
                    ">> Node {i} responed with {:?} public keys.",
                    response_keys.len()
                );
                responses.push(response_keys);
            }
            Err(err) => {
                println!(">> Node {i} responed with an error: {err}");
            }
        }
        // todo: timeout if node too long to respond
        i += 1;
    }

    // Check whether sufficiently many nodes have advertised the same key.
    // For this, identify each advertised key entry by its unique hash and count how many have been received
    // In this sample code we just keep the first such key.
    for response_by_node in responses.iter() {
        let mut advertised_public_keys_by_node: HashSet<[u8; 32]> = HashSet::new(); // make sure we count each advertised key once
        for key_entry in response_by_node.iter() {
            let h = get_public_key_entry_digest(key_entry);
            advertised_public_keys_by_node.insert(h);
            advertised_public_keys.insert(h, key_entry.clone());
        }
        for &h in advertised_public_keys_by_node.iter() {
            if !advertised_public_keys_count.contains_key(&h) {
                advertised_public_keys_count.insert(h, 0);
            }
            *advertised_public_keys_count.get_mut(&h).unwrap() += 1
        }
    }

    let mut advertised_key_option: Option<PublicKeyEntry> = None;
    for (h, count) in advertised_public_keys_count.iter() {
        if *count >= quorum {
            advertised_key_option = Some(advertised_public_keys.get(h).unwrap().clone());
            break;
        }
    }
    let advertised_key_entry: PublicKeyEntry = match advertised_key_option {
        Some(advertised_key_entry) => advertised_key_entry,
        None => return Ok(()), // If no public key was advertised by sufficiently many nodes, it is not safe to encrypt.
    };

    // Use the public key to encrypt
    println!(
        ">> Using public key with id {:?} to encrypt.",
        advertised_key_entry.id
    );
    let public_key = PublicKey::deserialize(&advertised_key_entry.key).unwrap();
    // todo: Do the following over an Rpc endpoint
    let (request, _) = create_decryption_request(30, (&public_key));

    // Submit the decryption request to the nodes.
    let mut i = 0;
    for conn in connections.iter_mut() {
        println!(">> Sending decryption request to server {i}.");
        let response = conn.decrypt(request.clone()).await.unwrap();
        i += 1;
    }

    Ok(())
}

fn get_public_key_entry_digest(key_entry: &PublicKeyEntry) -> [u8; 32] {
    let mut digest = HASH256::new();
    digest.process_array(&key_entry.id.as_bytes());
    digest.process_array(&key_entry.key);
    let h = digest.hash();
    h
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
        let (id, ip, port) = peer.clone();
        let addr = format!("http://[{ip}]:{port}");
        connections.push(
            ThresholdCryptoLibraryClient::connect(addr.clone())
                .await
                .unwrap(),
        );
    }
    println!(">> Connected.");
    connections
}

async fn connect_to_all_dockerized() -> Vec<ThresholdCryptoLibraryClient<tonic::transport::Channel>>
{
    // ips of tendermint nodes, rpc endpoints of threshold app
    let peers = vec![
        (0, String::from("192.167.10.2"), 51000),
        (1, String::from("192.167.10.3"), 51000),
        (2, String::from("192.167.10.4"), 51000),
        (3, String::from("192.167.10.5"), 51000),
    ];
    let mut connections = Vec::new();
    for peer in peers.iter() {
        let (id, ip, port) = peer.clone();
        let addr = format!("http://[{ip}]:{port}");
        connections.push(
            ThresholdCryptoLibraryClient::connect(addr.clone())
                .await
                .unwrap(),
        );
    }
    connections
}

fn create_decryption_request(sn: u32, pk: &PublicKey) -> (DecryptRequest, Ciphertext) {
    let ciphertext = create_ciphertext(sn, pk);
    let req = DecryptRequest {
        ciphertext: ciphertext.serialize().unwrap(),
        key_id: None,
    };
    (req, ciphertext)
}
/* 
fn create_decrypt_sync_request(sn: u32, pk: &PublicKey) -> (DecryptSyncRequest, Ciphertext) {
    let ciphertext = create_ciphertext(sn, pk);
    let req = DecryptSyncRequest {
        ciphertext: ciphertext.serialize().unwrap(),
        key_id: None,
    };
    (req, ciphertext)
}*/

fn create_ciphertext(sn: u32, pk: &PublicKey) -> Ciphertext {
    let mut params = ThresholdCipherParams::new();
    let msg_string = format!("Test message {}", sn);
    let msg: Vec<u8> = msg_string.as_bytes().to_vec();
    let label = format!("Label {}", sn);
    let ciphertext = ThresholdCipher::encrypt(&msg, label.as_bytes(), pk, &mut params).unwrap();
    ciphertext
}
