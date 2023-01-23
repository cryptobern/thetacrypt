use std::{io, vec};
use std::{thread, time};
use tokio::task::JoinHandle;
use tonic::{Status, Response};

use cosmos_crypto::proto::scheme_types::{Group, ThresholdScheme};
use cosmos_crypto::interface::{ThresholdCipher, ThresholdCipherParams, Ciphertext};
use cosmos_crypto::keys::{PublicKey};

use thetacrypt_proto::protocol_types::threshold_crypto_library_client::ThresholdCryptoLibraryClient;
use thetacrypt_proto::protocol_types::{GetDecryptResultRequest};
use thetacrypt_proto::protocol_types::{DecryptRequest, DecryptReponse};
use thetacrypt_proto::protocol_types::{DecryptSyncRequest, DecryptSyncReponse};
use protocols::keychain::KeyChain;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // abci_app_emulation().await?;
    get_encrypted_tx();
    Ok(())
}


// test_multiple_local_servers() tests basic communication for nodes that run locally on the main host.
// It is meant to test the basic network logic RpcRequestHandler, MessageForwarder, etc.
// To run it, start *four* server instances with peer ids 1-4, listening on localhost ports 50051-50054.
// They should be able to connect to each other.
async fn test_multiple_local_servers() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file("conf/keys_1.json")?; 
    let pk = key_chain_1.get_key_by_type(ThresholdScheme::Sg02, Group::Bls12381)?.key.get_public_key();
    let (request, _) = create_decryption_request(1, &pk);
    let (request2, _) = create_decryption_request(2, &pk);

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
        let _ = conn.decrypt(request2.clone()).await.unwrap();
        i += 1;
    }

    Ok(())
}


// test_multiple_local_servers() tests basic communication for nodes that run locally on the main host.
// It is meant to test the basic network logic RpcRequestHandler, MessageForwarder, etc.
// To run it, start *four* server instances with peer ids 1-4, listening on localhost ports 50051-50054.
// They should be able to connecto to each other.
async fn test_multiple_local_sync() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file("conf/keys_1.json")?; 
    let pk = key_chain_1.get_key_by_type(ThresholdScheme::Sg02, Group::Bls12381)?.key.get_public_key();
    let (request, _) = create_decrypt_sync_request(100, &pk);
    let (request2, _) = create_decrypt_sync_request(101, &pk);

    let mut connections = connect_to_all_local().await;

    // Send decrypt_sync request
    let mut i = 1;
    let mut handles= Vec::new();
    for conn in connections.iter_mut(){
        println!(">> Sending decrypt_sync request with sn=100 to server {i}.");
        let mut conn_clone = conn.clone();
        let request_clone = request.clone();
        let handle: JoinHandle<Result<Result<Response<DecryptSyncReponse>, Status>, io::Error>> = tokio::spawn(async move {
            let response = conn_clone.decrypt_sync(request_clone).await;
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
        println!(">> Sending AGAIN decrypt_sync request with sn=100 to server {i}.");
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

    // Send a second decrypt_sync request
    let mut i = 1;
    let mut handles= Vec::new();
    for conn in connections.iter_mut(){
        println!(">> Sending decrypt_sync request with sn=101 to server {i}.");
        let mut conn_clone = conn.clone();
        let request_clone = request2.clone();
        let handle: JoinHandle<Result<Result<Response<DecryptSyncReponse>, Status>, io::Error>> = tokio::spawn(async move {
            let response = conn_clone.decrypt_sync(request_clone).await;
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

    Ok(())
}

fn get_encrypted_tx(){
    let key_chain_1: KeyChain = KeyChain::from_file("conf/keys_1.json").unwrap(); 
    let pk = key_chain_1.get_key_by_type(ThresholdScheme::Sg02, Group::Bls12381).unwrap().key.get_public_key();
    let ctxt = create_ciphertext(1, &pk);
    println!("{:?}", ctxt.serialize().unwrap());
    
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