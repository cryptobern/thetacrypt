use theta_proto::proxy_api::{proxy_api_client::ProxyApiClient, ForwardShareRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello there! I'm the client!");

    let mut client = ProxyApiClient::connect("http://localhost:30000").await?;

    let request = ForwardShareRequest{
        data: "Hello World".to_owned().into_bytes(),
    };

    let response = client.forward_share(request).await.expect("Client RPC request failed");

    println!("RESPONSE={:?}", response);
    Ok(())
}