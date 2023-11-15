use thetacrypt_blockchain_stub::proto::blockchain_stub::{blockchain_stub_client::BlockchainStubClient, ForwardShareRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello there! I'm the client!");

    let mut client = BlockchainStubClient::connect("http://localhost:50000").await?;

    let request = ForwardShareRequest{
        data: "Hello World".to_owned().into_bytes(),
    };

    let response = client.forward_share(request).await.expect("Client RPC request failed");

    println!("RESPONSE={:?}", response);
    Ok(())
}