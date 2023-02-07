use std::process::exit;

use log::{error, info};

use protocols::{
    keychain::KeyChain,
    server::{cli, config, start_server},
};

#[tokio::main]
async fn main() {
    env_logger::init();

    let version = env!("CARGO_PKG_VERSION");
    info!("Starting server, version: {}", version);

    let cli = cli::parse();

    info!(
        "Loading configuration from file: {}",
        cli.config_file
            .to_str()
            .unwrap_or("Unable to print path, was not valid UTF-8"),
    );
    let cfg = match config::from_file(&cli.config_file) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("{}", e);
            exit(1);
        }
    };

    info!(
        "Loading keychain from file: {}",
        cli.keychain_file
            .to_str()
            .unwrap_or("Unable to print path, was not valid UTF-8")
    );
    let keychain = match KeyChain::from_file(&cli.keychain_file) {
        Ok(key_chain) => key_chain,
        Err(e) => {
            error!("{}", e);
            exit(1);
        }
    };

    start_server(&cfg, keychain).await;

    info!("Server is running");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received interrupt signal, shutting down");
            return;
        }
    }
}
