use std::path::PathBuf;

use clap::Parser;

/// CLI arguments of the server binary.
#[derive(Parser, Debug)]
#[command(about = format!("Server application {}", env!("CARGO_PKG_VERSION")))]
pub struct P2PCli {
    #[arg(long, help = "Path to JSON-encoded configuration.")]
    pub config_file: PathBuf
}