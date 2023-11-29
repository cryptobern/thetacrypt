use std::process::exit;

use clap::Parser;
use env_logger::init;
use log::{error, info};
use theta_schemes::keys::key_chain::KeyChain;

use theta_proto::protocol_types::threshold_crypto_library_client::ThresholdCryptoLibraryClient;
use theta_proto::protocol_types::KeyRequest;
use utils::client::cli::ClientCli;
use utils::client::types::ClientConfig;

/*
Short example program that retrieves all available public keys from the network
and imports them to a local keychain.
*/

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init();

    let version = env!("CARGO_PKG_VERSION");
    info!("Starting server, version: {}", version);

    let client_cli = ClientCli::parse();
    let mut keychain = KeyChain::new();

    info!(
        "Loading configuration from file: {}",
        client_cli
            .config_file
            .to_str()
            .unwrap_or("Unable to print path, was not valid UTF-8"),
    );
    let config = match ClientConfig::from_file(&client_cli.config_file) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("{}", e);
            exit(1);
        }
    };

    let mut connections = connect_to_all_local(config).await;
    let response = connections[0].get_public_keys(KeyRequest {}).await;
    if response.is_ok() {
        let response = response.unwrap();
        let keys = &response.get_ref().keys;
        if keychain.import_public_keys(keys).is_ok() {
            println!(">> Successfully imported public keys from server.");
            println!("{}", keychain.to_string());
        }
    } else {
        println!("Error fetching public keys!");
    }

    Ok(())
}

async fn connect_to_all_local(
    config: ClientConfig,
) -> Vec<ThresholdCryptoLibraryClient<tonic::transport::Channel>> {
    let mut connections = Vec::new();
    for peer in config.peers.iter() {
        let ip = peer.ip.clone();
        let port = peer.rpc_port;
        let addr = format!("http://[{ip}]:{port}");
        connections.push(
            ThresholdCryptoLibraryClient::connect(addr.clone())
                .await
                .unwrap(),
        );
    }
    println!(">> Established connection to network.");
    connections
}
