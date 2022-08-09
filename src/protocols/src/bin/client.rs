// pub mod requests {
//     tonic::include_proto!("requests");
// }

use std::collections::{HashMap, HashSet};
use std::{fs, io, vec};
use std::{thread, time};

use futures::stream::TryBufferUnordered;
// use network::config::localnet_config::config_service::get_rpc_listen_addr;
use network::config::tendermint_net::config_service::*;
use cosmos_crypto::keys::{PublicKey, PrivateKey};
use mcore::hash256::HASH256;

use cosmos_crypto::proto::scheme_types::{Group, ThresholdScheme};
use protocols::proto::protocol_types::threshold_crypto_library_client::ThresholdCryptoLibraryClient;
use protocols::proto::protocol_types::{self, GetDecryptResultRequest};
use protocols::proto::protocol_types::{PushDecryptionShareRequest};
use protocols::proto::protocol_types::{GetPublicKeysForEncryptionRequest, GetPublicKeysForEncryptionResponse, PublicKeyEntry};
use protocols::proto::protocol_types::{DecryptRequest, DecryptReponse};
use protocols::proto::protocol_types::{DecryptSyncRequest, DecryptSyncReponse};

use cosmos_crypto::dl_schemes::ciphers::sg02::{Sg02ThresholdCipher, Sg02PrivateKey, Sg02PublicKey, Sg02Ciphertext};
use cosmos_crypto::interface::{ThresholdCipher, ThresholdCipherParams, Serializable, DecryptionShare};
use protocols::keychain::KeyChain;
use cosmos_crypto::interface::Ciphertext;
use rand::prelude::SliceRandom;
use rand::thread_rng;
use serde::Serialize;
use tokio::task::JoinHandle;
use tonic::codegen::http::response;
use tonic::{Request, Status, Code, Response};


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    test_multiple_local_servers().await?;
    test_multiple_local_sync().await?;
    // abci_app_emulation().await?;
    Ok(())
}

// test_single_server() tests basic protocol behaviour. It does not test network communication, as it emulates
// the rest of the servers by computing decryption shares and sending them to the single server.
// To run it, start *one* server instance with peer id 1. Ignore the messages of the server about trying to connect to the P2P network.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_single_server() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = connect_to_one_local().await;

    // Read keys from file
    println!("Reading keys from keychain.");
    let key_chain_1: KeyChain = KeyChain::from_file("conf/keys_1.json")?; 
    let sk_sg02_bls12381_1 = key_chain_1.get_key_by_type(ThresholdScheme::Sg02, Group::Bls12381)?.key;
    
    // sk of rep 2 to create share. Only for test
    let key_chain_2: KeyChain = KeyChain::from_file("conf/keys_2.json")?;
    let sk_sg02_bls12381_2 = key_chain_2.get_key_by_type(ThresholdScheme::Sg02, Group::Bls12381)?.key;

    // sk of rep 3 to create share. Only for test
    let key_chain_3: KeyChain = KeyChain::from_file("conf/keys_3.json")?;
    let sk_sg02_bls12381_3 = key_chain_3.get_key_by_type(ThresholdScheme::Sg02, Group::Bls12381)?.key;

    // sk of rep 4 to create share. Only for test
    let key_chain_4: KeyChain = KeyChain::from_file("conf/keys_4.json")?;
    let sk_sg02_bls12381_4 = key_chain_4.get_key_by_type(ThresholdScheme::Sg02, Group::Bls12381)?.key;

    let pk_sg02_bls12381 = sk_sg02_bls12381_1.get_public_key();
    let k = sk_sg02_bls12381_1.get_threshold();
    println!("Reading keys done.");

    let (request, ciphertext) = create_decryption_request(1, &pk_sg02_bls12381);
    let (request2, ciphertext2) = create_decryption_request(2, &pk_sg02_bls12381);

    // Decryption request 1 
    println!(">> Sending decryption request 1.");
    let response = client.decrypt(request.clone()).await?;
    println!("RESPONSE={:?}", response);
    let decrypt_response = response.get_ref();
    

    // RESEND Decryption request 1 
    println!(">> Sending AGAIN decryption request 1.");
    let response = client.decrypt(request).await.expect_err("This should return an error.");
    println!("RESPONSE={:?}", response);
    assert!(response.code() == Code::AlreadyExists);
    
    // Decryption request 1, share id: 2
    println!(">> Sending decryption share. instance_id: {:?} share id: 2", decrypt_response.instance_id.clone());
    let share_2 = get_push_share_request(k, &ciphertext, sk_sg02_bls12381_2.clone(), decrypt_response.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_2)).await?;
    println!("RESPONSE={:?}", put_share_response);
    

    // Decryption request 2
    println!(">> Sending decryption request 2.");
    let response2 = client.decrypt(request2).await?;
    println!("RESPONSE={:?}", response2);
    let decrypt_response2 = response2.get_ref();

    // Decryption request 2, share id: 2
    println!(">> Sending decryption share. instance_id: {:?} share id: 2", decrypt_response2.instance_id.clone());
    let share_2 = get_push_share_request(k, &ciphertext2, sk_sg02_bls12381_2.clone(), decrypt_response2.instance_id.clone());
    let put_share_response2 = client.push_decryption_share(Request::new(share_2)).await?;
    println!("RESPONSE={:?}", put_share_response2);
    

    // Decryption request 1, Test what happens with DUPLICATE shares, share id 2
    println!(">> Sending DUPLICATE decryption share. instance id: {:?}, share id: 2", decrypt_response.instance_id.clone());
    let share_2 = get_push_share_request(k, &ciphertext, sk_sg02_bls12381_2.clone(), decrypt_response.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_2)).await?;
    println!("RESPONSE={:?}", put_share_response);
    
    // Decryption request 1, share id 3
    println!(">> Sending decryption share. instance id: {:?}, share id: 3", decrypt_response.instance_id.clone());
    let share_3 = get_push_share_request(k, &ciphertext, sk_sg02_bls12381_3.clone(), decrypt_response.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_3)).await?;
    println!("RESPONSE={:?}", put_share_response);

    // Decryption request 1, Test what happens with REDUNDANT shares, share id 4
    println!(">> Sending REDUNDANT decryption share. instance id: {:?}, share id: 4", decrypt_response.instance_id.clone());
    let share_4 = get_push_share_request(k, &ciphertext, sk_sg02_bls12381_4.clone(), decrypt_response.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_4)).await?;
    println!("RESPONSE={:?}", put_share_response);
    
    // Delay
    thread::sleep(time::Duration::from_millis(1000));

    // Decryption request 1, Test AGAIN what happens with REDUNDANT shares, share id 4
    println!(">> Sending REDUNDANT decryption share. instance id: {:?}, share id: 4", decrypt_response.instance_id.clone());
    let share_4 = get_push_share_request(k, &ciphertext, sk_sg02_bls12381_4.clone(), decrypt_response.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_4)).await?;
    println!("RESPONSE={:?}", put_share_response);


    // Decryption request 2, share id 3
    println!(">> Sending decryption share. instance id: {:?}, share id: 3", decrypt_response2.instance_id.clone());
    let share_3 = get_push_share_request(k, &ciphertext2, sk_sg02_bls12381_3.clone(), decrypt_response2.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_3)).await?;
    println!("RESPONSE={:?}", put_share_response);
 
    // Delay
    thread::sleep(time::Duration::from_millis(1000));

    // Decryption request 2, Test what happens with REDUNDANT shares, share id 4
    println!(">> Sending decryption share. instance id: {:?}, share id: 4", decrypt_response2.instance_id.clone());
    let share_4 = get_push_share_request(k, &ciphertext2, sk_sg02_bls12381_4.clone(), decrypt_response2.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_4)).await?;
    println!("RESPONSE={:?}", put_share_response);
 
    // Delay
    thread::sleep(time::Duration::from_millis(1000));
    
    // Decryption request 2, Test what happens with REDUNDANT shares, share id 4
    println!(">> Sending decryption share. instance id: {:?}, share id: 4", decrypt_response2.instance_id.clone());
    let share_4 = get_push_share_request(k, &ciphertext2, sk_sg02_bls12381_4.clone(), decrypt_response2.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_4)).await?;
    println!("RESPONSE={:?}", put_share_response);

    // Delay
    // thread::sleep(time::Duration::from_millis(1000));

    // INVALID Decryption request 3
    println!(">> Sending INVALID decryption request 3.");
    let PublicKey::Sg02(pk_sg02_bls12381_inner) = pk_sg02_bls12381;
    let (request3, ciphertext3) = create_tampered_sg02_decryption_request(3, &pk_sg02_bls12381_inner);
    let response3 = client.decrypt(request3).await.unwrap();
    println!("RESPONSE={:?}", response);
    let decrypt_response3 = response3.get_ref();

    // Share for INVALID Request, Decryption request 1, share id: 2
    println!(">> Sending decryption share. instance_id: {:?} share id: 2", decrypt_response3.instance_id.clone());
    
    let share_1 = get_push_share_request(k, &Ciphertext::Sg02(ciphertext3), sk_sg02_bls12381_1.clone(), decrypt_response3.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_1)).await?;
    println!("RESPONSE={:?}", put_share_response);

    Ok(())
}

// test_multiple_local_servers() tests basic communication for nodes that run locally on the main host.
// It is meant to test the basic network logic RpcRequestHandler, MessageForwarder, etc.
// To run it, start *four* server instances with peer ids 1-4, listening on localhost ports 50051-50054. They should be able to connecto to each other.
// #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_multiple_local_servers() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file("conf/keys_1.json")?; 
    let pk = key_chain_1.get_key_by_type(ThresholdScheme::Sg02, Group::Bls12381)?.key.get_public_key();
    let (request, ciphertext) = create_decryption_request(1, &pk);
    let (request2, ciphertext2) = create_decryption_request(2, &pk);

    let mut connections = connect_to_all_local().await;

    // Ask for decrypt result before sending decrypt request
    let mut i = 1;
    let get_result_request = GetDecryptResultRequest{ instance_id: String::from("Some instance that does not exist yet.") };
    for conn in connections.iter_mut(){
        println!(">> Sending get_decrypt_result request to server {i}.");
        let response = conn.get_decrypt_result(get_result_request.clone()).await.expect("This should not return Err");
        let get_result_response = response.into_inner();
        assert!(get_result_response.is_started == false);
        assert!(get_result_response.is_finished == false);
        assert!(get_result_response.plaintext == None);
        i += 1;
    }

    // Send decrypt request 1
    let mut i = 1;
    let mut instance_id = String::new();
    for conn in connections.iter_mut(){
        println!(">> Sending decryption request 1 to server {i}.");
        let response = conn.decrypt(request.clone()).await.expect("This should not return Err");
        instance_id = response.get_ref().instance_id.clone();
        
        // Immediately ask for decrypt result. The instance cannot have finished at this point
        if i <= 2 {
            let get_result_request = GetDecryptResultRequest{ instance_id: instance_id.clone() };
            println!(">> Sending get_decrypt_result request to server {i}.");
            let response = conn.get_decrypt_result(get_result_request.clone()).await.expect("This should not return Err");
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
    let mut i = 1;
    let get_result_request = GetDecryptResultRequest{ instance_id: instance_id.clone() };
    for conn in connections.iter_mut(){
        println!(">> Sending get_decrypt_result request to server {i}.");
        let response = conn.get_decrypt_result(get_result_request.clone()).await.expect("This should not return Err");
        let get_result_response = response.into_inner();
        assert!(get_result_response.is_started == true);
        assert!(get_result_response.is_finished == true);
        match get_result_response.plaintext{
            Some(plaintext) => {
                println!(">> Decrypted plaintext: {:?}.", String::from_utf8(plaintext).unwrap());
            },
            None => panic!("This should return Some(plaintext)."),
        }
        i += 1;
    }

    // Send decrypt request 2
    let mut i = 1;
    for conn in connections.iter_mut(){
        println!(">> Sending decryption request 2 to server {i}.");
        let response = conn.decrypt(request2.clone()).await.unwrap();
        i += 1;
    }

    Ok(())
}


// test_multiple_local_servers() tests basic communication for nodes that run locally on the main host.
// It is meant to test the basic network logic RpcRequestHandler, MessageForwarder, etc.
// To run it, start *four* server instances with peer ids 1-4, listening on localhost ports 50051-50054. They should be able to connecto to each other.
// #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_multiple_local_sync() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file("conf/keys_1.json")?; 
    let pk = key_chain_1.get_key_by_type(ThresholdScheme::Sg02, Group::Bls12381)?.key.get_public_key();
    let (request, ciphertext) = create_decrypt_sync_request(1, &pk);
    let (request2, ciphertext2) = create_decrypt_sync_request(2, &pk);

    let mut connections = connect_to_all_local().await;

    // Send decrypt_sync request
    let mut i = 1;
    let mut handles= Vec::new();
    for conn in connections.iter_mut(){
        println!(">> Sending decrypt_sync request 1 to server {i}.");
        let mut conn2 = conn.clone();
        let request2 = request.clone();
        let handle: JoinHandle<Result<Result<Response<DecryptSyncReponse>, Status>, io::Error>> = tokio::spawn(async move {
            let response = conn2.decrypt_sync(request2).await;
            Ok(response)
        });
        handles.push(handle);
        i += 1;
    }

    for handle in handles {
        let result = handle.await.expect("The task being joined has panicked.")?;
        let response = result.expect("This should not return Err");
        let plaintext = response.into_inner().plaintext.expect("This should return some plaintext");
        println!(">> Decrypted plaintext: {:?}.", String::from_utf8(plaintext).unwrap());
    };

    // Send DUPLICATE decrypt_sync request. The RPC call should return and error
    let mut i = 1;
    let mut handles= Vec::new();
    for conn in connections.iter_mut(){
        println!(">> Sending AGAIN decrypt_sync request 1 to server {i}.");
        let mut conn2 = conn.clone();
        let request2 = request.clone();
        let handle: JoinHandle<Result<Result<Response<DecryptSyncReponse>, Status>, io::Error>> = tokio::spawn(async move {
            let response = conn2.decrypt_sync(request2).await;
            Ok(response)
        });
        handles.push(handle);
        i += 1;
    }

    for handle in handles {
        let result = handle.await.expect("The task being joined has panicked.")?;
        assert!(result.is_err());
    };

    // Send INVALID-ciphertext decrypt_sync request. The RPC call should return a decryptSyncResponse, but the contained 'plaintext' field should be None.
    let PublicKey::Sg02(pk_sg02_bls12381) = pk;
    let (invalid_ctxt_request, original_ciphertext) = create_tampered_sg02_decrypt_sync_request(3, &pk_sg02_bls12381);
    let invalid_ctxt_decrypt_request = invalid_ctxt_request.into_inner();
    let mut i = 1;
    let mut handles= Vec::new();
    for conn in connections.iter_mut(){
        println!(">> Sending INVALID decrypt_sync request to server {i}.");
        let mut conn2 = conn.clone();
        let request2 = invalid_ctxt_decrypt_request.clone();
        let handle: JoinHandle<Result<Result<Response<DecryptSyncReponse>, Status>, io::Error>> = tokio::spawn(async move {
            let response = conn2.decrypt_sync(request2).await;
            Ok(response)
        });
        handles.push(handle);
        i += 1;
    }

    for handle in handles {
        let result = handle.await.expect("The task being joined has panicked.")?;
        let response = result.expect("This should not return Err");
        let plaintext = response.into_inner().plaintext;
        assert!(plaintext == None);
        // println!(">> Decrypted plaintext: {:?}.", String::from_utf8(plaintext).unwrap());
    };

    Ok(())
}


// test_multiple_local_servers_backlog() tests the backlog functionality on nodes that run locally on the main host.
// To run it, start *four* server instances with peer ids 1-4, listening on localhost ports 50051-50054. They should be able to connecto to each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_multiple_local_servers_backlog() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file("conf/keys_1.json")?; 
    let pk = key_chain_1.get_key_by_type(ThresholdScheme::Sg02, Group::Bls12381)?.key.get_public_key();
    let (request, ciphertext) = create_decryption_request(1, &pk);
    let (request2, ciphertext2) = create_decryption_request(2, &pk);
    
    let mut connections = connect_to_all_local().await;

    let mut i = 1;
    for conn in connections.iter_mut(){
        // Send two decryption request to one server and wait before you send it to the next,
        println!(">> Sending decryption request 1 to server {i}.");
        let response = conn.decrypt(request.clone()).await.unwrap();
        println!(">> Sending decryption request 2 to server {i}.");
        let response2 = conn.decrypt(request2.clone()).await.unwrap();
        // Make this bigger than BACKLOG_WAIT_INTERVAL and smaller than BACKLOG_MAX_RETRIES * BACKLOG_WAIT_INTERVAL
        thread::sleep(time::Duration::from_millis(7000)); 
        i += 1;
    }
    Ok(())
}

// test_tendermint_servers() tests basic library functionality, such as the `decrypt` endpoint,
// for nodes that run on docker containers.
// To run it, start *four* threshold-library server instances with peer ids 1--4, 
// istening on ips 192.167.10.2--4 and port 50050. 
async fn test_tendermint_servers() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain: KeyChain = KeyChain::from_file("conf/keys_1.json")?; 
    let pk = key_chain.get_key_by_type(ThresholdScheme::Sg02, Group::Bls12381)?.key.get_public_key();
    let (request, ciphertext) = create_decryption_request(1, &pk);
    let (request2, ciphertext2) = create_decryption_request(2, &pk);

    let mut connections = connect_to_all_dockerized().await;            

    let mut i = 1;
    for conn in connections.iter_mut(){
        println!(">> Sending decryption request 1 to server {i}.");
        let response = conn.decrypt(request.clone()).await.expect("This should not return Err");
        i += 1;
    }

    // Send DUPLICATE requests
    let mut i = 1;
    for conn in connections.iter_mut(){
        println!(">> Sending DUPLICATE decryption request 1 to server {i}.");
        let response = conn.decrypt(request.clone()).await.expect_err("This should return Err");
        assert!(response.code() == Code::AlreadyExists);
        // let response2 = conn.decrypt(request2.clone()).await.unwrap();
        i += 1;
    }

    let mut i = 1;
    for conn in connections.iter_mut(){
        println!(">> Sending decryption request 2 to server {i}.");
        let response = conn.decrypt(request2.clone()).await.unwrap();
        // let response2 = conn.decrypt(request2.clone()).await.unwrap();
        // println!("RESPONSE={:?}", response);
        i += 1;
    }

    Ok(())
}


async fn simple_demo() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file("conf/keys_1.json")?; 
    let pk = key_chain_1.get_key_by_type(ThresholdScheme::Sg02, Group::Bls12381)?.key.get_public_key();
    let (request, ciphertext) = create_decryption_request(1, &pk);
    
    let mut connections = connect_to_all_local().await;

    let mut input = String::new();
    
    let mut i = 1;
    for conn in connections.iter_mut(){
        io::stdin().read_line(&mut input)?; 
        println!(">> Sending decryption request 1 to server {i}.");
        let response = conn.decrypt(request.clone()).await.unwrap();
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
    let mut advertised_public_keys: HashMap<[u8; 32], protocol_types::PublicKeyEntry> = HashMap::new();
    let mut advertised_public_keys_count: HashMap<[u8; 32], u32> = HashMap::new();
    
    // Ask all the nodes for their available public keys. We say each node "advertises" some public keys.
    let req = GetPublicKeysForEncryptionRequest{};
    let mut responses = Vec::new();
    let mut i = 1;
    for conn in connections.iter_mut(){
        println!(">> Sending a get-keys request to node {i}.");
        match conn.get_public_keys_for_encryption(req.clone()).await{
            Ok(response) => {
                let response_keys = response.into_inner().keys;
                println!(">> Node {i} responed with {:?} public keys.", response_keys.len());
                responses.push(response_keys);
            },
            Err(err) => {
                println!(">> Node {i} responed with an error: {err}");
            },
        }
        // todo: timeout if node too long to respond
        i += 1;
    }
    
    // Check whether sufficiently many nodes have advertised the same key.
    // For this, identify each advertised key entry by its unique hash and count how many have been received
    // In this sample code we just keep the first such key.
    for response_by_node in responses.iter(){
        let mut advertised_public_keys_by_node: HashSet::<[u8; 32]> = HashSet::new(); // make sure we count each advertised key once
        for key_entry in response_by_node.iter(){
            let h = get_public_key_entry_digest(key_entry);
            advertised_public_keys_by_node.insert(h);
            advertised_public_keys.insert(h, key_entry.clone());
        }
        for &h in advertised_public_keys_by_node.iter(){
            if ! advertised_public_keys_count.contains_key(&h) {
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
    let advertised_key_entry: PublicKeyEntry = match advertised_key_option{
        Some(advertised_key_entry) => advertised_key_entry,
        None => return Ok(()), // If no public key was advertised by sufficiently many nodes, it is not safe to encrypt.
    };
    
    // Use the public key to encrypt
    println!(">> Using public key with id {:?} to encrypt.", advertised_key_entry.id);
    let public_key = PublicKey::deserialize(&advertised_key_entry.key).unwrap();
    // todo: Do the following over an Rpc endpoint
    let (request, _) = create_decryption_request(1, (&public_key));

    // Submit the decryption request to the nodes.
    let mut i = 1;
    for conn in connections.iter_mut(){
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
        (0, String::from("127.0.0.1"), 50051),
        (1, String::from("127.0.0.1"), 50052),
        (2, String::from("127.0.0.1"), 50053),
        (3, String::from("127.0.0.1"), 50054)
    ];
    let mut connections = Vec::new();
    for peer in peers.iter() {
        let (id, ip, port) = peer.clone();
        let addr = format!("http://[{ip}]:{port}");
        connections.push(ThresholdCryptoLibraryClient::connect(addr.clone()).await.unwrap());
    }
    println!(">> Connected.");
    connections
}

async fn connect_to_all_dockerized() -> Vec<ThresholdCryptoLibraryClient<tonic::transport::Channel>> {
    // ips of tendermint nodes, rpc endpoints of threshold app
    let peers = vec![
        (0, String::from("192.167.10.2"), 50050),
        (1, String::from("192.167.10.3"), 50050),
        (2, String::from("192.167.10.4"), 50050),
        (3, String::from("192.167.10.5"), 50050)
    ];
    let mut connections = Vec::new();
    for peer in peers.iter() {
        let (id, ip, port) = peer.clone();
        let addr = format!("http://[{ip}]:{port}");
        connections.push(ThresholdCryptoLibraryClient::connect(addr.clone()).await.unwrap());
    }
    connections
}

async fn connect_to_one_local() -> ThresholdCryptoLibraryClient<tonic::transport::Channel> {
    ThresholdCryptoLibraryClient::connect("http://[::1]:50051").await.unwrap()
}

fn create_decryption_request(sn: u32, pk: &PublicKey) -> (DecryptRequest, Ciphertext) {
    let ciphertext = create_ciphertext(sn, pk);
    let req = DecryptRequest {
        ciphertext: ciphertext.serialize().unwrap(),
        key_id: None
    };
    (req, ciphertext)
}

fn create_decrypt_sync_request(sn: u32, pk: &PublicKey) -> (DecryptSyncRequest, Ciphertext) {
    let ciphertext = create_ciphertext(sn, pk);
    let req = DecryptSyncRequest {
        ciphertext: ciphertext.serialize().unwrap(),
        key_id: None
    };
    (req, ciphertext)
}

fn create_ciphertext(sn: u32, pk: &PublicKey) -> Ciphertext {
    let mut params = ThresholdCipherParams::new();
    let msg_string = format!("Test message {}", sn);
    let msg: Vec<u8> = msg_string.as_bytes().to_vec();
    let label = format!("Label {}", sn);
    let ciphertext = ThresholdCipher::encrypt(&msg, label.as_bytes(), pk, &mut params).unwrap();
    ciphertext
}

fn create_tampered_sg02_decryption_request(sn: u32, pk: &Sg02PublicKey) -> (tonic::Request<DecryptRequest>, Sg02Ciphertext) {
    let (original_ciphertext, tampered_ciphertext) = create_tampered_ciphertext(sn, pk);
    let req = DecryptRequest {
        ciphertext: tampered_ciphertext.serialize().unwrap(),
        key_id: None
    };
    (Request::new(req), original_ciphertext)
}

fn create_tampered_sg02_decrypt_sync_request(sn: u32, pk: &Sg02PublicKey) -> (tonic::Request<DecryptSyncRequest>, Sg02Ciphertext) {
    let (original_ciphertext, tampered_ciphertext) = create_tampered_ciphertext(sn, pk);
    let req = DecryptSyncRequest {
        ciphertext: tampered_ciphertext.serialize().unwrap(),
        key_id: None
    };
    (Request::new(req), original_ciphertext)
}

fn create_tampered_ciphertext(sn: u32, pk: &Sg02PublicKey) -> (Sg02Ciphertext, Sg02Ciphertext) {
    let mut params = ThresholdCipherParams::new();
    let msg_string = format!("Test message {}", sn);
    let msg: Vec<u8> = msg_string.as_bytes().to_vec();
    let label = format!("Label {}", sn);
    let original_ciphertext = Sg02ThresholdCipher::encrypt(&msg, label.as_bytes(), &pk, &mut params);
    let tampered_ciphertext = Sg02ThresholdCipher::test_tamper_ciphertext(&original_ciphertext);
    (original_ciphertext, tampered_ciphertext)
}

fn get_decryption_shares_permuted(k: u32, ctxt: &Ciphertext, sk: Vec<PrivateKey>) -> Vec<DecryptionShare> {
    let mut params = ThresholdCipherParams::new();
    let mut shares = Vec::new();
    for i in 0..k {
        shares.push(ThresholdCipher::partial_decrypt(ctxt,&sk[i as usize], &mut params).unwrap());
    }
    shares.shuffle(&mut thread_rng());
    shares
}

fn get_push_share_request(k: u16, ctxt: &Ciphertext, sk: PrivateKey, instance_id: String) -> PushDecryptionShareRequest {
    let mut params = ThresholdCipherParams::new();
    let decryption_share = ThresholdCipher::partial_decrypt(ctxt,&sk, &mut params).unwrap();
    PushDecryptionShareRequest {instance_id, decryption_share: decryption_share.serialize().unwrap()}
}