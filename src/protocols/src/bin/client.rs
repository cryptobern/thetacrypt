// pub mod requests {
//     tonic::include_proto!("requests");
// }

use std::{fs, io};
use std::{thread, time};
use cosmos_crypto::keys::{PublicKey, PrivateKey};
use protocols::pb::requests::{self, PushDecryptionShareRequest};
// use cosmos_crypto::dl_schemes::ciphers::bz03::Bz03ThresholdCipher;
use cosmos_crypto::dl_schemes::ciphers::sg02::{Sg02ThresholdCipher, Sg02PrivateKey, Sg02PublicKey, Sg02Ciphertext};
use cosmos_crypto::dl_schemes::dl_groups::dl_group::{Group};
use cosmos_crypto::interface::{ThresholdCipher, ThresholdCipherParams, Serializable, DecryptionShare, ThresholdScheme};
use protocols::keychain::KeyChain;
use protocols::pb::requests::threshold_crypto_library_client::ThresholdCryptoLibraryClient;
use protocols::pb::requests::{ThresholdDecryptionRequest, ThresholdDecryptionResponse};
use cosmos_crypto::interface::Ciphertext;
use rand::prelude::SliceRandom;
use rand::thread_rng;
use tonic::{Request, Status, Code};


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_demo().await?;
    Ok(())
}

// test_single_server() tests basic protocol behaviour. It does not test network communication, as it emulates
// the rest of the servers by computing decryption shares and sending them to the single server.
// To run it, start *one* server instance with peer id 1. Ignore the messages of the server about trying to connect to the P2P network.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_single_server() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = connect_one().await;

    // Read keys from file
    println!("Reading keys from keychain.");
    let key_chain_1: KeyChain = KeyChain::from_file("conf/keys_1.json")?; 
    let sk_sg02_bls12381_1 = key_chain_1.get_key_by_type(ThresholdScheme::SG02, Group::BLS12381)?.key;
    
    // sk of rep 2 to create share. Only for test
    let key_chain_2: KeyChain = KeyChain::from_file("conf/keys_2.json")?;
    let sk_sg02_bls12381_2 = key_chain_2.get_key_by_type(ThresholdScheme::SG02, Group::BLS12381)?.key;

    // sk of rep 3 to create share. Only for test
    let key_chain_3: KeyChain = KeyChain::from_file("conf/keys_3.json")?;
    let sk_sg02_bls12381_3 = key_chain_3.get_key_by_type(ThresholdScheme::SG02, Group::BLS12381)?.key;

    // sk of rep 4 to create share. Only for test
    let key_chain_4: KeyChain = KeyChain::from_file("conf/keys_4.json")?;
    let sk_sg02_bls12381_4 = key_chain_4.get_key_by_type(ThresholdScheme::SG02, Group::BLS12381)?.key;

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
    let PublicKey::SG02(pk_sg02_bls12381_inner) = pk_sg02_bls12381;
    let (request3, ciphertext3) = create_tampered_sg02_decryption_request(3, &pk_sg02_bls12381_inner);
    let response3 = client.decrypt(request3).await.unwrap();
    println!("RESPONSE={:?}", response);
    let decrypt_response3 = response3.get_ref();

    // Share for INVALID Request, Decryption request 1, share id: 2
    println!(">> Sending decryption share. instance_id: {:?} share id: 2", decrypt_response3.instance_id.clone());
    
    let share_1 = get_push_share_request(k, &Ciphertext::SG02(ciphertext3), sk_sg02_bls12381_1.clone(), decrypt_response3.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_1)).await?;
    println!("RESPONSE={:?}", put_share_response);

    Ok(())
}

// test_multiple_local_servers() tests basic communication for nodes that run locally on the main host.
// It is meant to test the basic network logic RpcRequestHandler, MessageForwarder, etc.
// To run it, start *four* server instances with peer ids 1-4, listening on localhost ports 50051-50054. They should be able to connecto to each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_multiple_local_servers() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file("conf/keys_1.json")?; 
    let pk = key_chain_1.get_public_key_by_type(ThresholdScheme::SG02, Group::BLS12381)?;
    let (request, ciphertext) = create_decryption_request(1, &pk);
    let (request2, ciphertext2) = create_decryption_request(2, &pk);

    let mut connections = connect_all().await;

    let mut i = 1;
    for conn in connections.iter_mut(){
        println!(">> Sending decryption request 1 to server {i}.");
        let response = conn.decrypt(request.clone()).await.expect("This should not return Err");
        i += 1;
    }

    let mut i = 1;
    for conn in connections.iter_mut(){
        println!(">> Sending decryption request 2 to server {i}.");
        let response = conn.decrypt(request2.clone()).await.unwrap();
        i += 1;
    }

    Ok(())
}


// test_multiple_local_servers_backlog() tests the backlog functionality on nodes that run locally on the main host.
// To run it, start *four* server instances with peer ids 1-4, listening on localhost ports 50051-50054. They should be able to connecto to each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_multiple_local_servers_backlog() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file("conf/keys_1.json")?; 
    let pk = key_chain_1.get_public_key_by_type(ThresholdScheme::SG02, Group::BLS12381)?;
    let (request, ciphertext) = create_decryption_request(1, &pk);
    let (request2, ciphertext2) = create_decryption_request(2, &pk);
    
    let mut connections = connect_all().await;

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

async fn simple_demo() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file("conf/keys_1.json")?; 
    let pk = key_chain_1.get_public_key_by_type(ThresholdScheme::SG02, Group::BLS12381)?;
    let (request, ciphertext) = create_decryption_request(1, &pk);
    
    let mut connections = connect_all().await;

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

async fn connect_all() -> Vec<ThresholdCryptoLibraryClient<tonic::transport::Channel>> {
    let peers = vec![
        (0, String::from("::1"), 50051),
        (1, String::from("::1"), 50052),
        (2, String::from("::1"), 50053),
        (3, String::from("::1"), 50054)
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

async fn connect_one() -> ThresholdCryptoLibraryClient<tonic::transport::Channel> {
    ThresholdCryptoLibraryClient::connect("http://[::1]:50051").await.unwrap()
}


fn create_decryption_request(sn: u32, pk: &PublicKey) -> (ThresholdDecryptionRequest, Ciphertext) {
    let mut params = ThresholdCipherParams::new();
    let msg_string = format!("Test message {}", sn);
    let msg: Vec<u8> = msg_string.as_bytes().to_vec();
    let label = format!("Label {}", sn);
    let ciphertext = ThresholdCipher::encrypt(&msg, label.as_bytes(), pk, &mut params).unwrap();
    let req = requests::ThresholdDecryptionRequest {
        ciphertext: ciphertext.serialize().unwrap(),
        key_id: None
    };
    (req, ciphertext)
    // (Request::new(req), ciphertext)
}

fn create_tampered_sg02_decryption_request(sn: u32, pk: &Sg02PublicKey) -> (tonic::Request<ThresholdDecryptionRequest>, Sg02Ciphertext) {
    let mut params = ThresholdCipherParams::new();
    let msg_string = format!("Test message {}", sn);
    let msg: Vec<u8> = msg_string.as_bytes().to_vec();
    let label = format!("Label {}", sn);
    let ciphertext = Sg02ThresholdCipher::encrypt(&msg, label.as_bytes(), &pk, &mut params);
    let tampered_ciphertext = Sg02ThresholdCipher::test_tamper_ciphertext(&ciphertext);
    let req = requests::ThresholdDecryptionRequest {
        ciphertext: tampered_ciphertext.serialize().unwrap(),
        key_id: None
    };
    (Request::new(req), ciphertext)
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