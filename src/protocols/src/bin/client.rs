// pub mod requests {
//     tonic::include_proto!("requests");
// }

use std::fs;

use cosmos_crypto::dl_schemes::ciphers::bz03::Bz03ThresholdCipher;
use cosmos_crypto::dl_schemes::ciphers::sg02::{Sg02ThresholdCipher, Sg02PrivateKey};
use cosmos_crypto::dl_schemes::dl_groups::bls12381::Bls12381;
use cosmos_crypto::dl_schemes::dl_groups::dl_group::DlGroup;
use cosmos_crypto::interface::{ThresholdCipher, ThresholdCipherParams, PrivateKey, Serializable};
use cosmos_crypto::rand::{RngAlgorithm, RNG};
use protocols::keychain::KeyChain;
use protocols::requests::threshold_crypto_library_client::ThresholdCryptoLibraryClient;
use protocols::requests::{ThresholdDecryptionRequest, ThresholdDecryptionResponse, self};
use cosmos_crypto::interface::Ciphertext;
use rand::prelude::SliceRandom;
use rand::thread_rng;
use tonic::Request;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ThresholdCryptoLibraryClient::connect("http://[::1]:50051").await?;

    // Read keys from file
    println!("Reading keys from keychain.");
    let keyfile = format!("keys_0.json");
    let key_chain_str = fs::read_to_string(keyfile).unwrap();
    let key_chain: KeyChain = serde_json::from_str(&key_chain_str).unwrap();
    println!("Reading keys done.");

    let sk_sg02_bls12381 = Sg02PrivateKey::<Bls12381>::deserialize(
                                                                            &key_chain.get_key(
                                                                                requests::ThresholdCipher::Sg02,
                                                                                requests::DlGroup::Bls12381,
                                                                                None)
                                                                            .unwrap())
                                                                            .unwrap();
    let request = create_decryption_request::<Sg02ThresholdCipher<Bls12381>>(1, &sk_sg02_bls12381.get_public_key());
    let response = client.decrypt(request).await?;

    println!("RESPONSE={:?}", response);

    let shares = get_decryption_shares_permuted(3,)
    
    Ok(())
}

fn create_decryption_request<C:ThresholdCipher>(sn: u32, pk: &C::TPubKey) -> tonic::Request<ThresholdDecryptionRequest> {
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
    Request::new(req)
}

fn get_decryption_shares_permuted<C: ThresholdCipher>(K: usize, ctxt: &C::CT, sk: &Vec<C::TPrivKey>) -> Vec<C::TShare> {
    let mut params = ThresholdCipherParams::new();
    let mut shares = Vec::new();
    for i in sk.get {
        shares.push(C::partial_decrypt(ctxt,&sk[i as usize], &mut params));
    }
    shares.shuffle(&mut thread_rng());
    shares
}