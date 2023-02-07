use std::path::PathBuf;

use clap::Parser;

/// Parse the user-supplied CLI arguments.
pub fn parse() -> CLI {
    CLI::parse()
}

/// CLI interface of the server binary.
#[derive(Parser, Debug)]
#[command(about = format!("Server application {}", env!("CARGO_PKG_VERSION")))]
pub struct CLI {
    #[arg(long, help = "Path to JSON-encoded configuration.")]
    pub config_file: PathBuf,

    #[arg(long, help = "Path to JSON-encoded keychain.")]
    pub keychain_file: PathBuf,
}
