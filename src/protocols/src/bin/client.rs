use std::path::PathBuf;
use std::{io, vec};

use protocols::keychain::KeyChain;
use schemes::interface::Serializable;
use schemes::keys::PublicKey;
use schemes::{
    group::Group,
    interface::{Ciphertext, ThresholdCipher, ThresholdCipherParams, ThresholdScheme},
};

use thetacrypt_proto::protocol_types::threshold_crypto_library_client::ThresholdCryptoLibraryClient;
use thetacrypt_proto::protocol_types::DecryptRequest;

// Send a single decrypt() request.
// To run it, start *four* server instances with peer ids 1-4, listening on localhost ports 51000-51003.
// They should be able to connect to each other.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_chain_1: KeyChain = KeyChain::from_file(&PathBuf::from("conf/keys_1.json"))?;
    let pk = key_chain_1
        .get_key_by_scheme_and_group(ThresholdScheme::Sg02, Group::Bls12381)?
        .sk
        .get_public_key();
    let (request, _) = create_decryption_request(1, &pk);

    let mut connections = connect_to_all_local().await;

    let mut input = String::new();

    let mut i = 0;
    for conn in connections.iter_mut() {
        io::stdin().read_line(&mut input)?;
        println!(">> Sending decryption request 1 to server {i}.");
        let _ = conn.decrypt(request.clone()).await.unwrap();
        // let response2 = conn.decrypt(request2.clone()).await.unwrap();
        // println!("RESPONSE={:?}", response);
        i += 1;
    }
    Ok(())
}

fn create_decryption_request(sn: u32, pk: &PublicKey) -> (DecryptRequest, Ciphertext) {
    let ciphertext = create_ciphertext(sn, pk);
    let req = DecryptRequest {
        ciphertext: ciphertext.serialize().unwrap(),
        key_id: None,
    };
    (req, ciphertext)
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
    println!(">> Connected.");
    connections
}

fn create_ciphertext(sn: u32, pk: &PublicKey) -> Ciphertext {
    let mut params = ThresholdCipherParams::new();
    let msg_string = format!("Test message {}", sn);
    let msg: Vec<u8> = msg_string.as_bytes().to_vec();
    let label = format!("Label {}", sn);
    let ciphertext = ThresholdCipher::encrypt(&msg, label.as_bytes(), pk, &mut params).unwrap();
    ciphertext
}
