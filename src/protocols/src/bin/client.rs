// pub mod requests {
//     tonic::include_proto!("requests");
// }

use std::{fs, io};
use std::{thread, time};
// use network::config::localnet_config::config_service::get_rpc_listen_addr;
use network::config::docker_config::config_service::*;
use protocols::pb::requests::{self, PushDecryptionShareRequest};
use cosmos_crypto::dl_schemes::ciphers::bz03::Bz03ThresholdCipher;
use cosmos_crypto::dl_schemes::ciphers::sg02::{Sg02ThresholdCipher, Sg02PrivateKey, Sg02PublicKey, Sg02Ciphertext};
use cosmos_crypto::dl_schemes::dl_groups::bls12381::Bls12381;
use cosmos_crypto::dl_schemes::dl_groups::dl_group::DlGroup;
use cosmos_crypto::interface::{ThresholdCipher, ThresholdCipherParams, PrivateKey, Serializable};
use cosmos_crypto::rand::{RngAlgorithm, RNG};
use protocols::keychain::KeyChain;
use protocols::pb::requests::threshold_crypto_library_client::ThresholdCryptoLibraryClient;
use protocols::pb::requests::{ThresholdDecryptionRequest, ThresholdDecryptionResponse};
use cosmos_crypto::interface::Ciphertext;
use rand::prelude::SliceRandom;
use rand::thread_rng;
use tonic::{Request, Status, Code};


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // test_multiple_local_servers().await
    // test_multiple_local_servers_backlog().await
    test_docker_servers().await
}

async fn test_single_server() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ThresholdCryptoLibraryClient::connect("http://[::1]:50050").await?;

    // Read keys from file
    println!("Reading keys from keychain.");
    let key_chain_0: KeyChain = KeyChain::from_file("conf/keys_0.json"); 
    let key_entry = &key_chain_0.get_key(requests::ThresholdCipher::Sg02, requests::DlGroup::Bls12381,None).unwrap();
    let sk_sg02_bls12381 =  Sg02PrivateKey::<Bls12381>::deserialize(key_entry).unwrap();
    println!("Reading keys done.");
    
    // sk of rep 1 to create share. Only for test
    let key_chain_1: KeyChain = KeyChain::from_file("conf/keys_1.json");
    let key_entry_1 = &key_chain_1.get_key(requests::ThresholdCipher::Sg02, requests::DlGroup::Bls12381,None).unwrap();
    let sk_sg02_bls12381_1 =  Sg02PrivateKey::<Bls12381>::deserialize(key_entry_1).unwrap();

    // sk of rep 2 to create share. Only for test
    let key_chain_2: KeyChain = KeyChain::from_file("conf/keys_2.json");
    let key_entry_2 = &key_chain_2.get_key(requests::ThresholdCipher::Sg02, requests::DlGroup::Bls12381,None).unwrap();
    let sk_sg02_bls12381_2 =  Sg02PrivateKey::<Bls12381>::deserialize(key_entry_2).unwrap();

    // sk of rep 3 to create share. Only for test
    let key_chain_3: KeyChain = KeyChain::from_file("conf/keys_3.json");
    let key_entry_3 = &key_chain_3.get_key(requests::ThresholdCipher::Sg02, requests::DlGroup::Bls12381,None).unwrap();
    let sk_sg02_bls12381_3 =  Sg02PrivateKey::<Bls12381>::deserialize(key_entry_3).unwrap();

    let k = sk_sg02_bls12381.get_threshold();
    let (request, ciphertext) = create_decryption_request::<Sg02ThresholdCipher<Bls12381>>(1, &sk_sg02_bls12381.get_public_key());
    let (request2, ciphertext2) = create_decryption_request::<Sg02ThresholdCipher<Bls12381>>(2, &sk_sg02_bls12381.get_public_key());
    

    // Decryption request 1 
    println!(">> Sending decryption request 1.");
    let response = client.decrypt(request.clone()).await.unwrap();
    println!("RESPONSE={:?}", response);
    let decrypt_response = response.get_ref();

    // RESEND Decryption request 1 
    println!(">> Sending AGAIN decryption request 1.");
    let response = client.decrypt(request).await;
    println!("RESPONSE={:?}", response);
    
    // Decryption request 1, share id: 2
    println!(">> Sending decryption share. instance_id: {:?} share id: 2", decrypt_response.instance_id.clone());
    let share_1 = get_push_share_request::<Sg02ThresholdCipher<Bls12381>>(k, &ciphertext, sk_sg02_bls12381_1.clone(), decrypt_response.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_1)).await?;
    println!("RESPONSE={:?}", put_share_response);
    

    // Decryption request 2
    println!(">> Sending decryption request 2.");
    let response2 = client.decrypt(request2).await.unwrap();
    println!("RESPONSE={:?}", response2);
    let decrypt_response2 = response2.get_ref();

    // Decryption request 2, share id: 2
    println!(">> Sending decryption share. instance_id: {:?} share id: 2", decrypt_response2.instance_id.clone());
    let share_1 = get_push_share_request::<Sg02ThresholdCipher<Bls12381>>(k, &ciphertext2, sk_sg02_bls12381_1.clone(), decrypt_response2.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_1)).await?;
    println!("RESPONSE={:?}", put_share_response);
    

    // Decryption request 1, Test what happens with DUPLICATE shares, share id 2
    println!(">> Sending DUPLICATE decryption share. instance id: {:?}, share id: 2", decrypt_response.instance_id.clone());
    let share_1 = get_push_share_request::<Sg02ThresholdCipher<Bls12381>>(k, &ciphertext, sk_sg02_bls12381_1.clone(), decrypt_response.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_1)).await?;
    println!("RESPONSE={:?}", put_share_response);
    
    // Decryption request 1, share id 3
    println!(">> Sending decryption share. instance id: {:?}, share id: 3", decrypt_response.instance_id.clone());
    let share_2 = get_push_share_request::<Sg02ThresholdCipher<Bls12381>>(k, &ciphertext, sk_sg02_bls12381_2.clone(), decrypt_response.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_2)).await?;
    println!("RESPONSE={:?}", put_share_response);

    // Decryption request 1, Test what happens with REDUNDANT shares, share id 4
    println!(">> Sending REDUNDANT decryption share. instance id: {:?}, share id: 4", decrypt_response.instance_id.clone());
    let share_3 = get_push_share_request::<Sg02ThresholdCipher<Bls12381>>(k, &ciphertext, sk_sg02_bls12381_3.clone(), decrypt_response.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_3)).await?;
    println!("RESPONSE={:?}", put_share_response);
    
    // Delay
    thread::sleep(time::Duration::from_millis(1000));

    // Decryption request 1, Test what happens with REDUNDANT shares, share id 4
    println!(">> Sending REDUNDANT decryption share. instance id: {:?}, share id: 4", decrypt_response.instance_id.clone());
    let share_3 = get_push_share_request::<Sg02ThresholdCipher<Bls12381>>(k, &ciphertext, sk_sg02_bls12381_3.clone(), decrypt_response.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_3)).await?;
    println!("RESPONSE={:?}", put_share_response);


    // Decryption request 2, share id 3
    println!(">> Sending decryption share. instance id: {:?}, share id: 3", decrypt_response2.instance_id.clone());
    let share_2 = get_push_share_request::<Sg02ThresholdCipher<Bls12381>>(k, &ciphertext2, sk_sg02_bls12381_2.clone(), decrypt_response2.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_2)).await?;
    println!("RESPONSE={:?}", put_share_response);
 
    // Delay
    thread::sleep(time::Duration::from_millis(1000));

    // Decryption request 2, Test what happens with REDUNDANT shares, share id 4
    println!(">> Sending decryption share. instance id: {:?}, share id: 4", decrypt_response2.instance_id.clone());
    let share_3 = get_push_share_request::<Sg02ThresholdCipher<Bls12381>>(k, &ciphertext2, sk_sg02_bls12381_3.clone(), decrypt_response2.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_3)).await?;
    println!("RESPONSE={:?}", put_share_response);
 
    // Delay
    thread::sleep(time::Duration::from_millis(1000));
    
    // Decryption request 2, Test what happens with REDUNDANT shares, share id 4
    println!(">> Sending decryption share. instance id: {:?}, share id: 4", decrypt_response2.instance_id.clone());
    let share_3 = get_push_share_request::<Sg02ThresholdCipher<Bls12381>>(k, &ciphertext2, sk_sg02_bls12381_3.clone(), decrypt_response2.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_3)).await?;
    println!("RESPONSE={:?}", put_share_response);

    // Delay
    thread::sleep(time::Duration::from_millis(1000));

    // INVALID Decryption request 3
    let (request3, ciphertext3) = create_tampered_sg02_decryption_request(3, &sk_sg02_bls12381.get_public_key());
    println!(">> Sending INVALID decryption request 3.");
    let response3 = client.decrypt(request3).await.unwrap();
    println!("RESPONSE={:?}", response);
    let decrypt_response3 = response3.get_ref();

    // Share for INVALID Request, Decryption request 1, share id: 2
    println!(">> Sending decryption share. instance_id: {:?} share id: 2", decrypt_response3.instance_id.clone());
    let share_1 = get_push_share_request::<Sg02ThresholdCipher<Bls12381>>(k, &ciphertext3, sk_sg02_bls12381_1.clone(), decrypt_response3.instance_id.clone());
    let put_share_response = client.push_decryption_share(Request::new(share_1)).await?;
    println!("RESPONSE={:?}", put_share_response);

    Ok(())
}

async fn test_multiple_local_servers() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain: KeyChain = KeyChain::from_file("conf/pk.json"); 
    let pk = Sg02PublicKey::<Bls12381>::deserialize(&key_chain.get_key(requests::ThresholdCipher::Sg02, requests::DlGroup::Bls12381, None).unwrap()).unwrap();
    let (request, ciphertext) = create_decryption_request::<Sg02ThresholdCipher<Bls12381>>(1, &pk);
    let (request2, ciphertext2) = create_decryption_request::<Sg02ThresholdCipher<Bls12381>>(2, &pk);

    let peers = vec![
        (0, String::from("0.0.0.0"), 50051),
        (1, String::from("0.0.0.0"), 50052),
        (2, String::from("0.0.0.0"), 50053),
        (3, String::from("0.0.0.0"), 50054)
    ];
    
    let mut connections = Vec::new();
    for peer in peers.iter() {
        let (id, ip, port) = peer.clone();
        let addr = format!("http://[{ip}]:{port}");
        connections.push(ThresholdCryptoLibraryClient::connect(addr.clone()).await.unwrap());
    }            

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

async fn test_multiple_local_servers_backlog() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain: KeyChain = KeyChain::from_file("conf/pk.json"); 
    let pk = Sg02PublicKey::<Bls12381>::deserialize(&key_chain.get_key(requests::ThresholdCipher::Sg02, requests::DlGroup::Bls12381, None).unwrap()).unwrap();
    let (request, ciphertext) = create_decryption_request::<Sg02ThresholdCipher<Bls12381>>(1, &pk);
    let (request2, ciphertext2) = create_decryption_request::<Sg02ThresholdCipher<Bls12381>>(2, &pk);
    
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

    let mut i = 1;
    for conn in connections.iter_mut(){
        println!(">> Sending decryption request 1 to server {i}.");
        let response = conn.decrypt(request.clone()).await.unwrap();
        println!(">> Sending decryption request 2 to server {i}.");
        let response2 = conn.decrypt(request2.clone()).await.unwrap();
        thread::sleep(time::Duration::from_millis(7000)); // Make this bigger than BACKLOG_WAIT_INTERVAL
        i += 1;
    }
    Ok(())
}

async fn test_docker_servers() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain: KeyChain = KeyChain::from_file("conf/pk.json"); 
    let pk = Sg02PublicKey::<Bls12381>::deserialize(&key_chain.get_key(requests::ThresholdCipher::Sg02, requests::DlGroup::Bls12381, None).unwrap()).unwrap();
    let (request, ciphertext) = create_decryption_request::<Sg02ThresholdCipher<Bls12381>>(1, &pk);
    // let (request2, ciphertext2) = create_decryption_request::<Sg02ThresholdCipher<Bls12381>>(2, &pk);

    const TENDERMINT_CONFIG_PATH: &str = "../network/src/config/docker_config/config.toml";

    let config = load_config(TENDERMINT_CONFIG_PATH.to_string());

    let conn_addr = format!("{}{}", "http://0.0.0.0:", config.rpc_port);
    println!(">> rpc addr: {}", conn_addr);
    let mut rpc_conn = ThresholdCryptoLibraryClient::connect(conn_addr.clone()).await.unwrap();
    println!(">> Sending decryption request 1 to server.");
    rpc_conn.decrypt(request.clone()).await.expect("This should not return Err");
    
    // let mut connections = Vec::new();
    // for peer in peers.iter() {
    //     let (id, ip, port) = peer.clone();
    //     let addr = format!("http://[{ip}]:{port}");
    //     println!("rpc addr: {}", addr);
    //     connections.push(ThresholdCryptoLibraryClient::connect(addr.clone()).await.unwrap());
    // }            

    // let mut i = 1;
    // for conn in connections.iter_mut(){
    //     println!(">> Sending decryption request 1 to server {i}.");
    //     let response = conn.decrypt(request.clone()).await.expect("This should not return Err");
    //     i += 1;
    // }

    // // Send DUPLICATE requests
    // let mut i = 1;
    // for conn in connections.iter_mut(){
    //     println!(">> Sending DUPLICATE decryption request 1 to server {i}.");
    //     let response = conn.decrypt(request.clone()).await.expect_err("This should return Err");
    //     assert!(response.code() == Code::AlreadyExists);
    //     // let response2 = conn.decrypt(request2.clone()).await.unwrap();
    //     i += 1;
    // }

    // let mut i = 1;
    // for conn in connections.iter_mut(){
    //     println!(">> Sending decryption request 2 to server {i}.");
    //     let response = conn.decrypt(request2.clone()).await.unwrap();
    //     // let response2 = conn.decrypt(request2.clone()).await.unwrap();
    //     // println!("RESPONSE={:?}", response);
    //     i += 1;
    // }

    Ok(())
}

async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain: KeyChain = KeyChain::from_file("conf/pk.json"); 
    let pk = Sg02PublicKey::<Bls12381>::deserialize(&key_chain.get_key(requests::ThresholdCipher::Sg02, requests::DlGroup::Bls12381, None).unwrap()).unwrap();
    let (request, ciphertext) = create_decryption_request::<Sg02ThresholdCipher<Bls12381>>(1, &pk);
    let (request2, ciphertext2) = create_decryption_request::<Sg02ThresholdCipher<Bls12381>>(2, &pk);
    
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

    let mut input = String::new();
    
    let mut i = 1;
    for conn in connections.iter_mut(){
        // io::stdin().read_line(&mut input)?; 
        println!(">> Sending decryption request 1 to server {i}.");
        let response = conn.decrypt(request.clone()).await.unwrap();
        // let response2 = conn.decrypt(request2.clone()).await.unwrap();
        // println!("RESPONSE={:?}", response);
        i += 1;
    }
    Ok(())
}


fn create_decryption_request<C:ThresholdCipher>(sn: u32, pk: &C::TPubKey) -> (ThresholdDecryptionRequest, C::CT) {
    let mut params = ThresholdCipherParams::new();
    let msg_string = format!("Test message {}", sn);
    let msg: Vec<u8> = msg_string.as_bytes().to_vec();
    let label = format!("Label {}", sn);
    let ciphertext = C::encrypt(&msg, label.as_bytes(), pk, &mut params);
    let req = requests::ThresholdDecryptionRequest {
        algorithm: requests::ThresholdCipher::Sg02 as i32,
        dl_group: requests::DlGroup::Bls12381 as i32,
        ciphertext: ciphertext.serialize().unwrap(),
        key_id: String::from("sg02_bls12381")
    };
    (req, ciphertext)
    // (Request::new(req), ciphertext)
}

fn create_tampered_sg02_decryption_request(sn: u32, pk: &Sg02PublicKey<Bls12381>) -> (tonic::Request<ThresholdDecryptionRequest>, Sg02Ciphertext<Bls12381>) {
    let mut params = ThresholdCipherParams::new();
    let msg_string = format!("Test message {}", sn);
    let msg: Vec<u8> = msg_string.as_bytes().to_vec();
    let label = format!("Label {}", sn);
    let ciphertext = Sg02ThresholdCipher::<Bls12381>::encrypt(&msg, label.as_bytes(), &pk, &mut params);
    let tampered_ciphertext = Sg02ThresholdCipher::<Bls12381>::tamper_ciphertext(&ciphertext);
    let req = requests::ThresholdDecryptionRequest {
        algorithm: requests::ThresholdCipher::Sg02 as i32,
        dl_group: requests::DlGroup::Bls12381 as i32,
        ciphertext: tampered_ciphertext.serialize().unwrap(),
        key_id: String::from("sg02_bls12381")
    };
    (Request::new(req), ciphertext)
}

fn get_decryption_shares_permuted<C: ThresholdCipher>(k: u32, ctxt: &C::CT, sk: Vec<C::TPrivKey>) -> Vec<C::TShare> {
    let mut params = ThresholdCipherParams::new();
    let mut shares = Vec::new();
    for i in 0..k {
        shares.push(C::partial_decrypt(ctxt,&sk[i as usize], &mut params));
    }
    shares.shuffle(&mut thread_rng());
    shares
}

fn get_push_share_request<C: ThresholdCipher>(k: u32, ctxt: &C::CT, sk: C::TPrivKey, instance_id: String) -> PushDecryptionShareRequest {
    let mut params = ThresholdCipherParams::new();
    // let mut shares = Vec::new();
    // for i in sk.get_threshold() {
    //     shares.push(C::partial_decrypt(ctxt,&sk[i as usize], &mut params));
    // }
    // shares.shuffle(&mut thread_rng());
    // shares
    let decryption_share = C::partial_decrypt(ctxt,&sk, &mut params);
    PushDecryptionShareRequest {instance_id, decryption_share: decryption_share.serialize().unwrap()}
}