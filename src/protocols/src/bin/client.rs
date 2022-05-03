pub mod requests {
    tonic::include_proto!("requests");
}

use requests::threshold_protocol_client::ThresholdProtocolClient;
use requests::{ThresholdDecryptionRequest, ThresholdDecryptionResponse};


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ThresholdProtocolClient::connect("http://[::1]:50051").await?;

    let request = tonic::Request::new(ThresholdDecryptionRequest {
        sn: 1,
        algorithm: requests::ThresholdCipher::Sg02 as i32,
        dl_group: requests::DlGroup::Bls12381 as i32,
        threshold: 3,
        ciphertext: Vec::new(),
    });

    let response = client.decrypt(request).await?;

    println!("RESPONSE={:?}", response);
    
    Ok(())
}