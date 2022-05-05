// pub mod requests {
//     tonic::include_proto!("requests");
// }

use cosmos_crypto::dl_schemes::ciphers::bz03::Bz03ThresholdCipher;
use cosmos_crypto::dl_schemes::ciphers::sg02::Sg02ThresholdCipher;
use cosmos_crypto::dl_schemes::dl_groups::bls12381::Bls12381;
use cosmos_crypto::dl_schemes::dl_groups::dl_group::DlGroup;
use cosmos_crypto::interface::{ThresholdCipher, ThresholdCipherParams, PrivateKey};
use cosmos_crypto::rand::{RngAlgorithm, RNG};
use protocols::requests::threshold_protocol_client::ThresholdProtocolClient;
use protocols::requests::{ThresholdDecryptionRequest, ThresholdDecryptionResponse, self};
use cosmos_crypto::interface::Ciphertext;
use rand::prelude::SliceRandom;
use rand::thread_rng;
use tonic::Request;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ThresholdProtocolClient::connect("http://[::1]:50051").await?;

    const k: usize = 11; // threshold
    const N: usize = 15; // total number of secret shares
    let mut rng = RNG::new(RngAlgorithm::MarsagliaZaman);
    let sk_sg02_bls12381 = Sg02ThresholdCipher::generate_keys(k, N, Bls12381::new(), &mut rng);
    let sk_bz03_bls12381 = Bz03ThresholdCipher::generate_keys(k, N, Bls12381::new(), &mut rng);
    
    let request = create_decryption_request::<Sg02ThresholdCipher<Bls12381>>(1, &sk_sg02_bls12381[0].get_public_key());
    let response = client.decrypt(request).await?;

    println!("RESPONSE={:?}", response);
    
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
        ciphertext: ciphertext.get_msg(),
    };
    Request::new(req)
}

fn get_decryption_shares_permuted<C: ThresholdCipher>(K: usize, ctxt: &C::CT, sk: &Vec<C::TPrivKey>) -> Vec<C::TShare> {
    let mut params = ThresholdCipherParams::new();
    let mut shares = Vec::new();
    for i in 0..K {
        shares.push(C::partial_decrypt(ctxt,&sk[i as usize], &mut params));
    }
    shares.shuffle(&mut thread_rng());
    shares
}